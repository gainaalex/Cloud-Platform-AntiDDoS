import os
import json
import random
import urllib.parse
import http.server
import socketserver
import redis

REDIS_HOST = os.getenv('ROTLD_REDIS_HOST', 'redis_rotld')
PORT = int(os.getenv('ROTLD_PORT', 8080))

db = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

import socket


def resolve_docker_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"[*E] Nu am putut rezolva host-ul {hostname}: {e}")
        return "127.0.0.1"


def seed_rotld():
    print("[*I] ROTLD: Initializez datele de baza (Seed)...")

    mycloud_ip = resolve_docker_host('ns_mycloud')
    db.set("A:ns.mycloud.ro.", json.dumps({"type": "A", "ips": [mycloud_ip], "ttl": 120}))

    domenii_protejate = ["edu.tuiasi.ro.",
                         "api.mycloud.ro.",
                         "magazin.mycloud.ro.",
                         "emag.ro."]
    for dom in domenii_protejate:
        db.delete(f"A:{dom}")
        db.set(f"NS:{dom}", json.dumps({"type": "NS", "ips": ["ns.mycloud.ro."], "ttl": 120}))

    db.delete("NS:vatafu.ro.")
    db.set("A:vatafu.ro.", json.dumps({"type": "A", "ips": ["20.20.20.21"], "ttl": 10}))#trebuie 3600 asa e standardul
    db.set("A:digi.ro.", json.dumps({"type": "A", "ips": ["80.20.15.43"], "ttl": 10}))

    print(f"[*I] ROTLD: Seed complet. ns.mycloud.ro mapat la {mycloud_ip}")


class ROTLDHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == '/buy':
            if 'domain' in query:
                domain = query['domain'][0].lower()
                domain_ns = domain if domain.endswith('.') else domain + '.'

                if db.exists(f"A:{domain_ns}") or db.exists(f"NS:{domain_ns}"):
                    self.send_response(409)
                    self.end_headers()
                    self.wfile.write(b"ERR: Domeniul este deja inregistrat la ROTLD.")
                    return

                ip_final = query.get('ip', [f"89.100.{random.randint(1, 254)}.{random.randint(1, 254)}"])[0]

                db.set(f"A:{domain_ns}", json.dumps({"type": "A", "ips": [ip_final], "ttl": 10}))#trebuie 3600 in mod normal

                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"SUCCESS: {domain} inregistrat in ROTLD. IP public: {ip_final}\n".encode('utf-8'))
                return

        elif parsed.path == '/delegate_ns':
            if 'domain' in query and 'ns' in query:
                domain = query['domain'][0]
                ns = query['ns'][0]

                if not db.exists(f"A:{domain}") and not db.exists(f"NS:{domain}"):
                    self.send_error(404, "Domeniu inexistent")
                    return

                db.delete(f"A:{domain}")
                db.set(f"NS:{domain}", json.dumps({"type": "NS", "ips": [ns], "ttl": 120}))

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK: Delegare NS efectuata")
                return

        elif parsed.path == '/restore_a':
            if 'domain' in query and 'ip' in query:
                domain = query['domain'][0]
                ip = query['ip'][0]

                db.delete(f"NS:{domain}")
                db.set(f"A:{domain}", json.dumps({"type": "A", "ips": [ip], "ttl": 10})) #trebuie 3600 in mod normal

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK: Ruta nativa A restaurata")
                return

        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Bad Request")


if __name__ == "__main__":
    seed_rotld()
    server = socketserver.TCPServer(("0.0.0.0", PORT), ROTLDHandler)
    print(f"[*I] ROTLD API pornit pe portul {PORT}")
    server.serve_forever()