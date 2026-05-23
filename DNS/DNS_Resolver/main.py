import os
import socket
import json
import redis
from dnslib import DNSRecord, QTYPE, RR, A, RCODE
from dotenv import load_dotenv
import socketserver

# TODO: ma ocup de port naming conventions mai tarziu

load_dotenv()

#Parametrii DNS flood prevention
DNS_FLOOD_WINDOW = int(os.getenv('DNS_FLOOD_WINDOW', 1))
DNS_FLOOD_MAX_REQS = int(os.getenv('DNS_FLOOD_MAX_REQS', 80))
DNS_BAN_TIMEOUT = int(os.getenv('DNS_BAN_TIMEOUT', 120))



RESOLVER_NAME = os.getenv('RESOLVER_NAME', 'DNS_Resolver_Nx')
IP_BIND = os.getenv('IP_BIND', '0.0.0.0')
PORT_BIND = int(os.getenv('PORT_BIND', 5333))

NS_TARGET_IP = os.getenv('NS_TARGET_IP', '172.17.0.1')
NS_TARGET_PORT = int(os.getenv('NS_TARGET_PORT', 5334))

REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Conexiunea la cache-ul resolverului
db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

#!!! Rezolvam dinamic ip-ul containerului ROOT in Docker (daca e configurat asa in env)
ROOT_HOSTNAME = os.getenv('ROOT_HOSTNAME', 'dns_root')
try:
    ROOT_IPS = socket.gethostbyname(ROOT_HOSTNAME)
except Exception:
    ROOT_IPS = NS_TARGET_IP

SBelt = {"root": {"ips": [ROOT_IPS]}}

#aici verificam si aplicam load balancing pe lista de ip de tip A, nu CNAME/NS etc, asta ar fi ultimul pas
def aplica_load_balancing(qname):
    # load balancing folosit pentru ditribuirea cererilor intre POP returnate de Name Server
    # extrage ttl ul curent ramas in redis pentru a nu il reseta cand salvam rotirea
    ttl_ramas = db.ttl(qname)

    if ttl_ramas <= 0:
        return None, 0

    record_json = db.get(qname)
    if record_json:
        record = json.loads(record_json)
        if record.get('type') == 'A':
            pool = record.get('ips', [])
            if pool and len(pool) > 0:
                # rotire circulara (round robin)
                ip = pool.pop(0)
                pool.append(ip)

                # salvam ordinea modificata in redis, pastrand timpul de expirare ramas
                db.set(qname, json.dumps({'type': 'A', 'ips': pool}), ex=ttl_ramas)

                # returnam lista rotita si ttl ul pe care trebuie sa il dam clientului
                return list(pool), ttl_ramas

    return None, 0


def get_nearest_ancestor(qname):
    root_ip = SBelt["root"]["ips"][0]

    # verific daca un ancestor a mai fost cautat si s-a primit o referinta a unui NS
    labels = [l for l in qname.split('.') if l]
    search_names = [".".join(labels[i:]) + "." for i in range(len(labels))]
    search_names.append(".")

    for name in search_names:
        record_json = db.get(name)
        if record_json:
            record = json.loads(record_json)
            if record.get('type') == 'NS':
                print(f"[I]: ~CACHE NS HIT~ {RESOLVER_NAME} a gasit nearest ancestor pt {qname} -> {name}")
                returned_list=list(record.get('ips', []))
                returned_list.append(root_ip)#pentru orice eventualitate, cname uri care nu au primit si o lista de adrese efective, etc. Punem si adresa root ului
                return returned_list

    print(f"[I]: {RESOLVER_NAME} Nu a gasit delegari. Getting data from SBelt (Root):")
    return SBelt["root"]["ips"]


def interogare_iterativa(qname):
    # Case 1: Verific cache intern in Redis pt a verfica existenta adresei cerute
    #!!! Mecanismul de urmarire recursiva a aliasurilor direct din cache inainte de a iesi pe retea
    nume_cautat = qname
    max_cname_chain = 5 #pt a preveni loopwhole urile
    cname_hops = 0
    while cname_hops < max_cname_chain:
         pool_cname, ttl_cname = aplica_load_balancing(nume_cautat)
         if pool_cname:
             print(f"[I]: ~CACHE HIT~ {RESOLVER_NAME}: HIT din resolver cache pt {qname}")
             return pool_cname, ttl_cname #asta e cazul in care da hit din prima (a gasit efectiv adresa, fara cname) sau daca pe parcurs, de la a 2 a iteratie in colo cauta cname uri
         rec_cname_json = db.get(nume_cautat)
         if rec_cname_json:
             rec_cn = json.loads(rec_cname_json)
             if rec_cn.get('type') == 'CNAME':
                 nume_cautat = rec_cn.get('alias')
                 cname_hops += 1
                 continue
         break

    # P2: Creez SLIST cu rute ce ma pot duce la adresa ceruta
    #!!! Cautam nearest ancestor direct pentru aliasul la care a avansat rezolvarea din cache

    #cautam prin cache dupa NS uri prin parsarea domeniului (ex: edu.tuiasi.ro. -> cautam tuiasi.ro. , ro. si daca nu stim mergem la root)
    SLIST = get_nearest_ancestor(nume_cautat) #facem cautarea pe alias pentru a salva timp in parcurgerea arborelui(am fi ajuns sa cautam tot dupa acest alias si daca as fi ales qname, dar cu extra steps)

    MAX_HOPS = 10
    hops = 0

    print(f"[I]: {RESOLVER_NAME} -> Incep rezolvarea iterativa pentru {qname}")

    while hops < MAX_HOPS and len(SLIST) > 0:
        hops += 1
        target_ip = SLIST[0]
        print(f"[I]: ITERATIE {hops}: Interoghez NS la {target_ip}:53")

        try:
            cerere = DNSRecord.question(qname)
            #!!! Daca rulam pe un alias aflat din cache, intrebam reteaua direct despre el
            if nume_cautat != qname:
                cerere = DNSRecord.question(nume_cautat) #default qtype="A", qclass="IN"

            pachet_raspuns = cerere.send(target_ip, 53, timeout=2.0)
            raspuns = DNSRecord.parse(pachet_raspuns)

            # CASE 1: Raspuns autoritar (<=> AA=1)
            if getattr(raspuns.header, 'aa') == 1:
                # !!! parsarea pachetelor mixte (contin inregistrari CNAME | A)
                un_ip_salvat = False
                un_cname_salvat = False
                ttlMin = raspuns.rr[0].ttl if raspuns.rr else None  # cautam sa vedem daca nu cumva aceasta adresa e una sensitive si care are ttl f mic, prea mic pt a mai avea sens sa o stocam

                # !!! Cazul TTL mic: (TTL <= 1), trimitem direct datele fara sa mai accesam BD
                if ttlMin is not None and ttlMin <= 1:
                    ip_imediate = [str(rr.rdata) for rr in raspuns.rr if rr.rtype == QTYPE.A]
                    if ip_imediate:
                        print(f"[I]: [SUCCES] Received uncacheable volatile answer for {qname} (TTL: {ttlMin}s).")
                        return ip_imediate, ttlMin
                    else:
                        print(f"[I]: [FAIL] Received uncacheable volatile answer with no A records (posibil NXDOMAIN)")
                        return None, 0

                # !!! Cazul normal: Procesam si stocam in Redis inregistrarile cu TTL stabil (> 1)
                for rr in raspuns.rr:
                    nume_real = str(rr.rname)
                    if rr.rtype == QTYPE.A:
                        ip_num = str(rr.rdata)
                        pool_ex = []
                        rec_vechi = db.get(nume_real)
                        if rec_vechi:
                            data_v = json.loads(rec_vechi)
                            if data_v.get('type') == 'A':
                                pool_ex = data_v.get('ips', [])
                        if ip_num not in pool_ex:
                            pool_ex.append(ip_num)
                        db.set(nume_real, json.dumps({'type': 'A', 'ips': pool_ex}), ex=rr.ttl)
                        un_ip_salvat = True
                    elif rr.rtype == QTYPE.CNAME:
                        db.set(nume_real, json.dumps({'type': 'CNAME', 'alias': str(rr.rdata)}), ex=rr.ttl)
                        un_cname_salvat = True

                if un_ip_salvat or un_cname_salvat:
                    return interogare_iterativa(
                        qname)  # recautand dupa qname acoperim cazul unde alisul expira (ex edu.tuiasi.ro. in cname vatafu.cloud.net) iar cautarea adresei vatafu.cloud.net se termina dupa expirare

                # !!! Daca am trecut de tot si nu s-a salvat nimic, inseamna ca sectiunea Answer a fost goala sau fara inregistrari web utile
                print(f"[I]: [FAIL] Received authoritar answer : no adresses (posibil NXDOMAIN)")
                return None, 0

            # CASE 2: Referral
            elif len(raspuns.auth) > 0:
                new_slist = []
                ns_names = [str(rr.rdata) for rr in raspuns.auth if rr.rtype == QTYPE.NS]
                if not ns_names:
                    SLIST.pop(0)
                    continue

                zona_delegata = str(raspuns.auth[0].rname)

                # Looking for Glue Records
                for ns in ns_names:
                    for ar in raspuns.ar:
                        if str(ar.rname) == ns and ar.rtype == QTYPE.A:
                            #port_de_folosit = 5334 if str(ar.rdata) == NS_TARGET_IP else 5333
                            new_slist.append(str(ar.rdata))

                if new_slist:
                    SLIST = new_slist
                    # Extragem TTL ul delegarii (din Authority section)
                    ttl_delegare = raspuns.auth[0].ttl if raspuns.auth else 300

                    # Stocam delegarea in Redis cu TTL ul aferent
                    db.set(zona_delegata, json.dumps({'type': 'NS', 'ips': new_slist}), ex=ttl_delegare)

                    print(
                        f"[I]: REFFERAL Delegat catre {zona_delegata} (TTL: {ttl_delegare}s). SLIST actualizat. Reiau bucla")
                    continue
                else:
                    print(f"[E]: Referral fara Glue Records. Trec la urmatorul NS")
                    SLIST.pop(0)
                    continue

            # CASE 3: adresa invalida sau nu exista in sistem => trecem la urmatorul name domain in ierarhie
            else:
                SLIST.pop(0)

        except Exception as e:
            print(f"[*EROARE] Comunicarea a esuat la HOP {hops}: {e}")
            SLIST.pop(0)

    print(f"[EROARE] {RESOLVER_NAME} -> Resolver failed. (Prea multe HOP-uri sau SLIST gol).")
    return None, 0


class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket_curent = self.request[1]
        client_addr = self.client_address
        client_ip=client_addr[0]

        try:
            #DNS Flood prevention logic
            if (db.get(f"ban:{client_ip}")):
                print(f"[I]: [DDOS PREVENTION] IP: {client_ip} banned")
                return

            client_req_id=f"req:{client_ip}"
            nr_cereri_client=db.incr(client_req_id)

            if nr_cereri_client==1:
                db.expire(client_req_id, DNS_FLOOD_WINDOW)

            if nr_cereri_client>DNS_FLOOD_MAX_REQS:
                print(f"[I]: [DDOS DETECTED] IP:{client_ip} banned for sending {nr_cereri_client} requests per {DNS_FLOOD_WINDOW} seconds.")
                db.set(f"ban:{client_ip}", 1,ex=DNS_BAN_TIMEOUT)
                db.delete(client_req_id)
                return

            #dns resolver logic
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            print(f"\n==============================================")
            print(f"[I:] [REQUEST] De la {client_addr} pt -> {qname}")

            # Interogarea intoarce acum atat lista de IP-uri cat si TTL-ul curent din Redis
            ips_rezolvate, ttl_curent = interogare_iterativa(qname)

            reply = request.reply()
            if ips_rezolvate:
                # Adaugam fiecare IP din lista in pachetul final cu TTL-ul real, nu hardcodat
                for ip in ips_rezolvate:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl_curent))
                print(f"[I]: [RESPONSE] Trimit catre {client_addr} -> {ips_rezolvate} cu TTL {ttl_curent}s")
            else:
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                print(f"[I]: [RESPONSE] Domeniul nu a fost gasit (NXDOMAIN).")

            socket_curent.sendto(reply.pack(), client_addr)

        except Exception as e:
            print(f"[EROARE] Handler: {e}")


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass


if __name__ == "__main__":
    server = ThreadedUDPServer((IP_BIND, PORT_BIND), ThreadedUDPRequestHandler)
    print(f"[I:] {RESOLVER_NAME} STARTED.")
    print(f"[I:] ADDRESS:PORT -> {IP_BIND}:{PORT_BIND}")
    print(f"[I:] Hardcoded SBelt -> {SBelt}")
    print(f"[I:] DDOS Params -> Max {DNS_FLOOD_MAX_REQS} req/{DNS_FLOOD_WINDOW}s. Ban time: {DNS_BAN_TIMEOUT}s")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()