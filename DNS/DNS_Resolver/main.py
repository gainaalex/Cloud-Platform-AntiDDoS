import os
import socket
import json
import redis
import random
from dnslib import DNSRecord, QTYPE, RR, A, RCODE
from dotenv import load_dotenv
import socketserver

# TODO: ma ocup de port naming conventions mai tarziu

load_dotenv()

# Parametrii DNS flood prevention
DNS_FLOOD_WINDOW = int(os.getenv('DNS_FLOOD_WINDOW', 1))
DNS_FLOOD_MAX_REQS = int(os.getenv('DNS_FLOOD_MAX_REQS', 80))
DNS_BAN_TIMEOUT = int(os.getenv('DNS_BAN_TIMEOUT', 120))

NXDOMAIN_CACHE_TTL = int(os.getenv('NXDOMAIN_CACHE_TTL', 300))


RESOLVER_NAME = os.getenv('RESOLVER_NAME', 'DNS_Resolver_Nx')
IP_BIND = os.getenv('IP_BIND', '0.0.0.0')
PORT_BIND = int(os.getenv('PORT_BIND', 5333))

NS_TARGET_IP = os.getenv('NS_TARGET_IP', '172.17.0.1')
NS_TARGET_PORT = int(os.getenv('NS_TARGET_PORT', 5334))

REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Conexiunea la cache-ul resolverului
db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
# in redis, informatiile de tip A despre domeniul x sunt stocate A:x
#                           tip NS sunt stocate: NS:x
#                           tip CNAME sunt stocate: CNAME:x


ROOT_HOSTNAME = os.getenv('ROOT_HOSTNAME', 'dns_root')
try:
    ROOT_IPS = socket.gethostbyname(ROOT_HOSTNAME)
except Exception:
    ROOT_IPS = NS_TARGET_IP

SBelt = {"root": {"ips": [ROOT_IPS]}}




# aici verificam si aplicam load balancing pe lista de ip de tip A, nu CNAME/NS etc
def aplica_load_balancing(qname):
    # load balancing folosit pentru ditribuirea cererilor intre POP returnate de Name Server
    # extrage ttl ul curent ramas in redis pentru a nu il reseta cand salvam rotirea


    cache_key = f"A:{qname.lower()}"
    ttl_ramas = db.ttl(cache_key)

    if ttl_ramas <= 0:
        return None, 0

    record_json = db.get(cache_key)
    if record_json:
        record = json.loads(record_json)
        if record.get('type') == 'A':
            pool = record.get('ips', [])
            if pool and len(pool) > 0:
                rotatie = random.randint(0, len(pool) - 1)
                pool_rotit = pool[rotatie:] + pool[:rotatie]

                # returnam lista rotita si ttl ul pe care trebuie sa il dam clientului
                return pool_rotit, ttl_ramas

    return None, 0


def get_nearest_ancestor(qname):
    root_ip = SBelt["root"]["ips"][0]

    qname = qname.lower()

    # verific daca un ancestor a mai fost cautat si s-a primit o referinta a unui NS
    labels = [l for l in qname.split('.') if l]
    search_names = [".".join(labels[i:]) + "." for i in range(len(labels))]
    search_names.append(".")

    for name in search_names:
        cache_key = f"NS:{name}" # cautam NS urile asociate
        record_json = db.get(cache_key)
        record_ttl=db.ttl(cache_key)
        if record_json:
            record = json.loads(record_json)
            if record.get('type') == 'NS':
                print(f"[I]: ~CACHE NS HIT~ {RESOLVER_NAME} a gasit nearest ancestor pt {qname} -> {name} (TTL: {record_ttl})")
                returned_list = list(record.get('ips', []))
                returned_list.append(
                    root_ip)  # pentru orice eventualitate, cname uri care nu au primit si o lista de adrese efective, etc. Punem si adresa root ului
                return returned_list

    print(f"[I]: {RESOLVER_NAME} Nu a gasit delegari. Getting data from SBelt (Root):")
    return SBelt["root"]["ips"]


def interogare_iterativa(qname):
    nume_cautat = qname.lower()


    if db.get(f"NXDOMAIN:{nume_cautat}"):
        print(f"[I]: ~CACHE HIT~ {RESOLVER_NAME}: NXDOMAIN din cache pt {qname}")
        return None, 0

    # Case 1: Verific cache intern in Redis pt a verfica existenta adresei cerute
    pool_a, ttl_a = aplica_load_balancing(nume_cautat)
    if pool_a:
        print(f"[I]: ~CACHE HIT~ {RESOLVER_NAME}: HIT din resolver cache pt {qname}")
        return pool_a, ttl_a

    # Case 2 - Cache miss: Creez SLIST cu rute ce ma pot duce la adresa ceruta
    SLIST = get_nearest_ancestor(nume_cautat)

    MAX_HOPS = 10
    hops = 0

    print(f"[I]: {RESOLVER_NAME} -> Incep rezolvarea iterativa pentru {qname}")

    while hops < MAX_HOPS and len(SLIST) > 0:
        hops += 1
        target_ip = SLIST[0]
        print(f"[I]: ITERATIE {hops}: Interoghez NS la {target_ip}:53")

        try:
            cerere = DNSRecord.question(qname)
            pachet_raspuns = cerere.send(target_ip, 53, timeout=2.0)
            raspuns = DNSRecord.parse(pachet_raspuns)

            # CASE 1: Raspuns autoritar (<=> AA=1)
            if getattr(raspuns.header, 'aa') == 1:
                un_ip_salvat = False
                ttlMin = raspuns.rr[0].ttl if raspuns.rr else None  # cautam sa vedem daca nu cumva aceasta adresa e una sensitive si care are ttl f mic, prea mic pt a mai avea sens sa o stocam

                # Cazul cand e ttl mic (<=1): trimitem direct datele fara sa mai accesam BD
                if ttlMin is not None and ttlMin <= 1:
                    ip_imediate = [str(rr.rdata) for rr in raspuns.rr if rr.rtype == QTYPE.A]
                    if ip_imediate:
                        print(f"[I]: [SUCCES] Received uncacheable volatile answer for {qname} (TTL: {ttlMin}s).")
                        return ip_imediate, ttlMin
                    else:
                        print(f"[I]: [FAIL] Received uncacheable volatile answer with no A records (posibil NXDOMAIN)")
                        db.set(f"NXDOMAIN:{nume_cautat}", 1, ex=NXDOMAIN_CACHE_TTL)
                        return None, 0

                # !!! cazul basic: stocam in bd datele cu ttl mai mare de 1
                adrese_colectate = []
                nume_domeniu=None
                for rr in raspuns.rr:
                    if rr.rtype == QTYPE.A:
                        ip_num = str(rr.rdata)
                        if nume_domeniu is None:
                            nume_domeniu = str(rr.rname).lower()
                        if ip_num not in adrese_colectate:
                            adrese_colectate.append(ip_num)

                cache_key_a = f"A:{nume_domeniu}"

                if nume_domeniu: #practic daca nu mai e null inseamna ca e cel putin o inregistare
                    db.set(cache_key_a, json.dumps({'type': 'A', 'ips': adrese_colectate}), ex=ttlMin)
                    un_ip_salvat = True

                if un_ip_salvat:
                    return aplica_load_balancing(qname)

                # daca am ajuns aici inseamna ca e NXDOMAIN
                print(f"[I]: [FAIL] Received authoritar answer : no adresses (posibil NXDOMAIN)")

                db.set(f"NXDOMAIN:{nume_cautat}", 1, ex=NXDOMAIN_CACHE_TTL)
                return None, 0

            # CASE 2: Referral
            elif len(raspuns.auth) > 0:
                new_slist = []
                ns_names = [str(rr.rdata).lower() for rr in raspuns.auth if rr.rtype == QTYPE.NS]
                if not ns_names:
                    SLIST.pop(0)
                    continue

                zona_delegata = str(raspuns.auth[0].rname).lower()

                # Looking for Glue Records
                for ns in ns_names:
                    for ar in raspuns.ar:
                        if str(ar.rname).lower() == ns and ar.rtype == QTYPE.A:
                            new_slist.append(str(ar.rdata))

                if new_slist:
                    SLIST = new_slist

                    ttl_delegare = raspuns.auth[0].ttl if raspuns.auth else 300

                    # Stocam delegarea in Redis cu TTL ul aferent
                    db.set(f"NS:{zona_delegata}", json.dumps({'type': 'NS', 'ips': new_slist}), ex=ttl_delegare)

                    print(f"[I]: REFFERAL Delegat catre {zona_delegata} (TTL: {ttl_delegare}s). SLIST actualizat. Reiterez...")
                    continue
                else:
                    ###!!! Deoarece arhitectura e controlata, ne asteptam la Glue Records. Daca nu vin, ruta e corupta si sarim.
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
        client_ip = client_addr[0]

        try:

            if (db.get(f"ban:{client_ip}")):
                print(f"[I]: [DDOS PREVENTION] IP: {client_ip} banned")
                return

            client_req_id = f"req:{client_ip}"

            #cu pipeline pt a unii cererile atomice , pt a eficientiza timpul petrecut accesand bd ul
            pipe = db.pipeline()
            pipe.incr(client_req_id)#nr_cereri_client
            pipe.ttl(client_req_id)#ttl_curent
            rezultate_pipe = pipe.execute()

            nr_cereri_client = rezultate_pipe[0]
            ttl_curent = rezultate_pipe[1]

            if nr_cereri_client == 1 or ttl_curent == -1: #ttl -1 inseamna ca nu are ttl | ttl =-2 inseamna ca cheia nu exista
                db.expire(client_req_id, DNS_FLOOD_WINDOW)

            if nr_cereri_client > DNS_FLOOD_MAX_REQS:
                print(f"[I]: [DDOS DETECTED] IP:{client_ip} banned for sending {nr_cereri_client} requests per {DNS_FLOOD_WINDOW} seconds.")
                db.set(f"ban:{client_ip}", 1, ex=DNS_BAN_TIMEOUT)
                db.delete(client_req_id)
                return

            # dns resolver logic
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = request.q.qtype
            print(f"\n==============================================")
            print(f"[I:] [REQUEST] De la {client_addr} pt -> {qname}")

            #PT DNS AMPLIFICATION
            if qtype == 255:  # 255 este QTYPE.ANY
                print(f"[W]: [DNS AMPLIFICATION DETECTED] Cerere ANY blocata de la {client_addr}. Trimitem REFUSED.")
                reply = request.reply()
                reply.header.rcode = getattr(RCODE, 'REFUSED')
                socket_curent.sendto(reply.pack(), client_addr)
                return

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

            pachet_final = reply.pack()
            size_req = len(data)
            size_resp = len(pachet_final)

            # PT DNS AMPLIFICATION
            # daca raspunsul e mult mai mare decat cererea (Asimetrie de amplificare)
            # si rata de cereri de la acest IP e suspecta, activam flag-ul TC (truncated)
            if size_resp > (size_req * 5) and nr_cereri_client > (DNS_FLOOD_MAX_REQS / 2):
                print(f"[W]: [DNS AMPLIFICATION DETECTED] Detectat raspuns asimetric ({size_resp} bytes). Trunchiem pachetul.")
                reply_trunchiat = request.reply()
                reply_trunchiat.header.tc = 1  #conform RFC 1035
                socket_curent.sendto(reply_trunchiat.pack(), client_addr)
                return

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