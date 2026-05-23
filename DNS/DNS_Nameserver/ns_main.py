import os
import random
import socket
import json
import redis
from dnslib import DNSRecord, RR, A, NS, QTYPE, RCODE
from dotenv import load_dotenv
import database_population

load_dotenv()

NS_NAME = os.getenv('NS_NAME', 'NS-Principal')
IP_BIND = os.getenv('IP_BIND', '0.0.0.0')
PORT_BIND = int(os.getenv('PORT_BIND', 5334))

REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def porneste_server_ns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP_BIND, PORT_BIND))

    print(f"[I:] {NS_NAME} DNS Name Server started succesfully on ")
    print(f"[I:] ADDRESS:PORT-> {IP_BIND}:{PORT_BIND}")
    print(f"[I:] Connected on {REDIS_HOST}:{REDIS_PORT} via Redis\n")

    while True:
        try:
            # conform rfc1035 max 512 bytes per cerere
            data, addr = sock.recvfrom(512)
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).lower()
            qtype = request.q.qtype

            print(f"[I:] {NS_NAME} -> Req received from {addr}: {qname}")

            reply = request.reply()

            # name space ul are implementata doar logica necesara pentru a raspunde la cererile de IPv4 , nu IPv6/MX
            if qtype == QTYPE.A:
                record_a_json = db.get(f"A:{qname}")
                # Case 1: suntem autoritari (aem direct adresa ip in bd)
                if record_a_json:
                    reply.header.aa = 1
                    record = json.loads(record_a_json)
                    ips_list = record['ips']

                    if len(ips_list) > 1:
                        # load balancing la nivel de name domain
                        random.shuffle(ips_list)

                    for ip in ips_list:
                        reply.add_answer(RR(
                            rname=qname,
                            rtype=QTYPE.A,
                            rclass=1,
                            ttl=record['ttl'],
                            rdata=A(ip)
                        ))
                    print(f"[I:] {NS_NAME} -> [AUTH] RSP delivered for {addr} -> {ips_list} (TTL {record['ttl']})")

                # Case 2: daca nu suntem autoritari,cautam un NS la care sa facem forward
                else:
                    labels = [l for l in qname.split('.') if l]
                    search_names = [".".join(labels[i:]) + "." for i in range(len(labels))]
                    search_names.append(".")

                    delegat = False
                    for name in search_names:
                        record_ns_json = db.get(f"NS:{name}")
                        if record_ns_json:
                            reply.header.aa = 0
                            record_ns = json.loads(record_ns_json)
                            ns_list = record_ns['ips']  # Aici ips reprezinta de fapt numele serverelor de nume (ex: ns.rotld.ro.)

                            for ns_name in ns_list:

                                reply.add_auth(RR(name, QTYPE.NS, rdata=NS(ns_name), ttl=record_ns['ttl']))

                                # adaugam in additional (glue records) IP-ul NS-ului tot in Redis
                                glue_json = db.get(f"A:{ns_name}")
                                if glue_json:
                                    glue_record = json.loads(glue_json)
                                    for glue_ip in glue_record['ips']:
                                        reply.add_ar(RR(ns_name, QTYPE.A, rdata=A(glue_ip), ttl=glue_record['ttl']))

                            print(f"[I:] {NS_NAME} -> [REFERRAL] Delegat {name} catre {ns_list}")
                            delegat = True
                            break

                    #daca nu sunt delegat, atunci domeniul nu exista
                    if not delegat:
                        reply.header.aa = 1
                        reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                        print(f"[E:] {NS_NAME} -> {qname} is NXDOMAIN")

            sock.sendto(reply.pack(), addr)

        except Exception as e:
            print(f"[E:] Eroare la procesarea pachetului: {e}")


if __name__ == "__main__":
    print(f"[I:] {NS_NAME} -> Populez baza de date cu domeniile de test....")
    database_population.populeaza_redis()
    database_population.get_all_data()
    porneste_server_ns()