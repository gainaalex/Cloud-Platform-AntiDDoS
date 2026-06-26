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
    server = socketserver.TCPServer(("0.0.0.0", PORT), ROTLDHandler)
    print(f"[I] ROTLD API pornit pe portul {PORT}")
    server.serve_forever()