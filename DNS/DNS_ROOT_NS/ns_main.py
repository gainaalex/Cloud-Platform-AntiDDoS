import os
import random
import socket
import json
import redis
from dnslib import DNSRecord, RR, A, QTYPE, RCODE
from dotenv import load_dotenv
import database_population

load_dotenv()

NS_NAME = os.getenv('NS_NAME', 'NS-Principal')
IP_BIND = os.getenv('IP_BIND', '127.0.0.1')
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
            #conform rfc1035 max 512 bytes per cerere
            data, addr = sock.recvfrom(512)
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = request.q.qtype

            print(f"[I:]{NS_NAME} -> Req received from {addr}: {qname}")

            reply = request.reply()
            reply.header.aa = 1
            #name space ul are implementata doar logica necesara pentru a raspunde la cererile de IPv4 , nu IPv6/MX
            if qtype == QTYPE.A:
                record_json = db.get(qname)

                if record_json:
                    record = json.loads(record_json)
                    ips_list=record['ips']
                    r_type=record['type']
                    if len(ips_list)>1:
                        random.shuffle(ips_list)

                    for ip in ips_list:
                        reply.add_answer(RR(
                            rname=qname,
                            rtype=r_type,
                            rclass=1,
                            ttl=record['ttl'],
                            rdata=A(ip)
                        ))
                    print(f"[I:]{NS_NAME} -> RSP delivered for {addr} -> {ips_list}")
                else:
                    reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                    print(f"[E:]{NS_NAME} -> {qname} is NXDOMAIN")

            sock.sendto(reply.pack(), addr)

        except Exception as e:
            print(f"[E:] {e}")


if __name__ == "__main__":
    print(f"[I:] {NS_NAME}-> Populez baza de date cu domeniile de test....")
    database_population.populeaza_redis()
    database_population.get_all_data()
    porneste_server_ns()