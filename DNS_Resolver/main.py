import os
import socket
import threading
import time
from dnslib import DNSRecord, QTYPE, RR, A, RCODE
from dotenv import load_dotenv
import socketserver
#TODO: ma ocup de port naming conventions mai tarziu


load_dotenv()

RESOLVER_NAME = os.getenv('RESOLVER_NAME', 'DNS_Resolver_Nx')
IP_BIND = os.getenv('IP_BIND', '0.0.0.0')
PORT_BIND = int(os.getenv('PORT_BIND', 5333))

NS_TARGET_IP = os.getenv('NS_TARGET_IP', '172.17.0.1')
NS_TARGET_PORT = int(os.getenv('NS_TARGET_PORT', 5334))


SBelt = {"root": {"ips": NS_TARGET_IP, "port": NS_TARGET_PORT}}

dns_cache = {}
cache_lock = threading.Lock()


def aplica_load_balancing(qname):
    #load balancing folosit pentru ditribuirea cererilor intre POP returnate de Name Server (asta
    # daca serverele mele de prelucrare ar fi UNICAST, dar dat fiind ca sunt ANYCAST va fi cam inutilizat in aplicatia mea)
    # foloseste round_robin (nu e nevoie de ceva mai complex in arhitectura mea)
    with cache_lock:
        if qname in dns_cache and dns_cache[qname].get('type') == 'A':
            pool = dns_cache[qname]['data']
            if pool:
                ip = pool.pop(0)
                pool.append(ip)
                return ip
    return None

#verific daca un ancestor a mai fost cautat si s-a primit o referinta a unui NS (=Name Server) daca nu, returnez adresele date de SBELT
def get_nearest_ancestor(qname):
    labels = [l for l in qname.split('.') if l]
    search_names = [".".join(labels[i:]) + "." for i in range(len(labels))]
    search_names.append(".")

    with cache_lock:
        for name in search_names:
            if name in dns_cache and dns_cache[name].get('type') == 'NS':
                if time.time() < dns_cache[name]['expires']:
                    print(f"[I]: ~CACHE NS HIT~ {RESOLVER_NAME} a gasit nearest ancestor pt {qname} -> {name}")
                    return list(dns_cache[name]['data'])
                else:
                    del dns_cache[name] #sterge cererile cu ttl expirat

    print(f"[I]: {RESOLVER_NAME} Nu a gasit delegari. Getting data from SBelt (Root).")
    return [[SBelt["root"]["ips"], SBelt["root"]["port"]]]


def interogare_iterativa(qname):

    # P1: Verific cache intern pt a verfica existenta adresei cerute
    with cache_lock:
        if qname in dns_cache and dns_cache[qname].get('type') == 'A':
            if time.time() < dns_cache[qname]['expires']:
                print(f"[I]: ~CACHE HIT~ {RESOLVER_NAME}: HIT din resolver cache pt {qname}")
                return aplica_load_balancing(qname)
            else:
                print(f"[I]: ~CACHE EXPIRED~ {RESOLVER_NAME}: Cache expirat pentru {qname}")
                del dns_cache[qname]
    # Daca nu face match sau e expirata informatia cache-uita
    # P2: Creez SLIST cu rute ce ma pot duce la adresa ceruta
    SLIST = get_nearest_ancestor(qname)
    MAX_HOPS = 10
    hops = 0

    print(f"[I]: {RESOLVER_NAME} -> Incep rezolvarea iterativa pentru {qname}")

    while hops < MAX_HOPS and len(SLIST) > 0:
        hops += 1
        target_ip, target_port = SLIST[0]
        print(f"[I]: ITERATIE {hops}: Interoghez NS la {target_ip}:{target_port}")

        try:
            cerere = DNSRecord.question(qname)
            pachet_raspuns = cerere.send(target_ip, target_port, timeout=2.0)
            raspuns = DNSRecord.parse(pachet_raspuns)

            # CASE 1: Raspuns e autoritar (<=> AA=1)
            if getattr(raspuns.header, 'aa') == 1:
                ip_gasite = [str(rr.rdata) for rr in raspuns.rr if rr.rtype == QTYPE.A] #poate NS via answare va returna mai multe RR <=> multe adrese la care trebuie sa fac aici un eventual load balancing (nu e cazul)
                if ip_gasite:
                    with cache_lock:
                        dns_cache[qname] = {'type': 'A', 'data': ip_gasite, 'expires': time.time() + 60}
                    print(f"[I]: [SUCCES] Received an authoritar answare. Updating cache-ul cu: {ip_gasite}")
                    return aplica_load_balancing(qname)
                else:
                    print(f"[I]: [FAIL] Received an authoritar answare : no adresses (posibil NXDOMAIN)")
                    return None

            # CASE 2: Referral
            #conform standardului RFC 1034 in Authority gasim NS urile numele efective ale serverelor
            elif len(raspuns.auth) > 0:
                new_slist = []
                ns_names = [str(rr.rdata) for rr in raspuns.auth if rr.rtype == QTYPE.NS]
                if not ns_names:
                    SLIST.pop(0)
                    continue

                zona_delegata = str(raspuns.auth[0].rname)

                # Looking for Glue Records
                # aceste glue records sunt defapt adresele NS primite in Authority
                for ns in ns_names:
                    for ar in raspuns.ar:
                        if str(ar.rname) == ns and ar.rtype == QTYPE.A:
                            port_de_folosit = 5334 if str(ar.rdata) == NS_TARGET_IP else 5333
                            new_slist.append([str(ar.rdata), port_de_folosit])

                if new_slist:
                    SLIST = new_slist
                    with cache_lock:
                        dns_cache[zona_delegata] = {'type': 'NS', 'data': new_slist, 'expires': time.time() + 300}
                    print(f"[I]: REFFERAL Delegat catre {zona_delegata}. SLIST actualizat. Reiau bucla")
                    continue
                else:
                    print(f"[E]: Referral fara Glue Records. Trec la urmatorul NS")
                    SLIST.pop(0)
                    continue

            # CASE 3: Adresa invalida sau nu exista in sistemul meu
            else:
                SLIST.pop(0)

        except Exception as e:
            print(f"[EROARE] Comunicarea a esuat la HOP {hops}: {e}")
            SLIST.pop(0)

    print(f"[EROARE] {RESOLVER_NAME} -> Resolver failed. (Prea multe HOP-uri sau SLIST gol).")
    return None


class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket_curent = self.request[1]
        client_addr = self.client_address

        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname)
            print(f"\n==============================================")
            print(f"[I:] [REQUEST] De la {client_addr} pt -> {qname}")

            ip_rezolvat = interogare_iterativa(qname)

            reply = request.reply()
            if ip_rezolvat:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_rezolvat), ttl=60))
                print(f"[I]: [RESPONSE] Trimit catre {client_addr} -> {ip_rezolvat}")
            else:
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                print(f"[I]: [RESPONSE] Domeniul nu a fost gasit (NXDOMAIN).")

            socket_curent.sendto(reply.pack(), client_addr)

        except Exception as e:
            pass


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass


if __name__ == "__main__":
    server = ThreadedUDPServer((IP_BIND, PORT_BIND), ThreadedUDPRequestHandler)
    print(f"[I:] {RESOLVER_NAME} STARTED.")
    print(f"[I:] ADDRESS:PORT -> {IP_BIND}:{PORT_BIND}")
    print(f"[I:] Hardcoded SBelt -> {SBelt}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()