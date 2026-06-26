import os
import json
import time
import threading
import urllib.parse
import urllib.request
import http.server
import socketserver
import redis
import hmac
import hashlib

REDIS_HOST = os.getenv('MYCLOUD_REDIS_HOST', 'redis_mycloud')
PORT = int(os.getenv('API_PORT', 5000))
API_KEY = os.getenv('API_KEY', 'micunealta-secreta')
ROTLD_URL = os.getenv('ROTLD_API_URL', 'http://rotld_api:8080')

db = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

INITIAL_DATA = {
    "edu.tuiasi.ro.": "172.20.0.12:80",
    "mycloud.ro.": "172.20.0.10:80",
    "emag.ro": "127.121.5.65:80"
}


def seed_mycloud():
    print("[I] MyCloud: Initializez datele de baza (Seed)...")
    for domeniu, origin_ip in INITIAL_DATA.items():
        db.sadd("protected_domains", domeniu)
        db.set(f"origin:{domeniu.rstrip('.')}", origin_ip)
    print("[I] MyCloud: Seed complet")

#Functia de control a inregisrrarilor din MyCloud BD cu privire
#la adresele domeniilor protejate si POP active
def control_plane_loop():
    print("[I] Control Plane MyCloud running...")
    while True:
        try:
            domenii = db.smembers("protected_domains")
            ips_live = [k.split(":")[-1] for k in db.keys("heartbeat:POP:*")]
            if ips_live:
                for d in domenii:
                    db.set(f"A:{d}", json.dumps({"type": "A", "ips": ips_live, "ttl": 30}))
                    db.set(f"A:*.{d}", json.dumps({"type": "A", "ips": ips_live, "ttl": 30}))
            else:
                for d in domenii:
                    db.delete(f"A:{d}")
                    db.delete(f"A:*.{d}")
        except Exception:
            pass
        time.sleep(5)


class MyCloudHandler(http.server.BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    #Functia de autentificare se face pe baza unui timestamp si a unei semnaturi generate
    def verify_signature(self, domain, ip, ts_str, client_sig):
        try:
            req_time = int(ts_str)
            timp_container = int(time.time())
            diferenta = abs(timp_container - req_time)

            print(f"[DEBUG HMAC] Browser Time: {req_time} | Docker Time: {timp_container} | Diff: {diferenta}s")

            if diferenta > 3600:
                print("[E] Semnatura respinsa: Cererea e prea veche sau ceasul e desincronizat masiv.")
                return False

            payload = f"{domain}:{ip}:{ts_str}"
            expected = hmac.new(API_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected, client_sig):
                print(f"[E] Semnatura respinsa: HMAC Mismatch!")
                print(f"     Asteptat (Python): {expected}")
                print(f"     Primit (JS):       {client_sig}")
                return False

            print("[I] Semnatura valida. Tranzactie aprobata.")
            return True

        except Exception as e:
            print(f"[E] Eroare fatala in validare HMAC: {e}")
            return False

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if 'sig' not in query or 't' not in query:
            self.send_error(401, "Missing signature or timestamp")
            return

        client_sig = query['sig'][0]
        ts_str = query['t'][0]

        if parsed.path == '/register':
            if 'domain' in query and 'origin' in query:
                domain = query['domain'][0].lower().strip('.')
                origin = query['origin'][0]
                domain_ns = domain if domain.endswith('.') else domain + '.'

                if not self.verify_signature(domain, origin, ts_str, client_sig):
                    self.send_error(403, "Invalid signature")
                    return

                #Identificare tip domeniu
                #licenta.ro (Root Domain)
                #my.licenta.ro / *.licenta.ro (Subdomain)
                parti_domeniu = domain.split('.')
                is_subdomain = len(parti_domeniu) > 2 or domain.startswith('*.')

                if not is_subdomain:
                    #Daca e un domeniu, apelam ROTLD
                    try:
                        req_url = f"{ROTLD_URL}/delegate_ns?domain={domain_ns}&ns=ns.mycloud.ro."
                        req = urllib.request.Request(req_url, method='POST')
                        urllib.request.urlopen(req)

                        db.sadd("protected_domains", domain_ns)
                        print(f"[I] ROOT DOMAIN {domain} delegat in ROTLD si inregistrat in CDN.")
                    except urllib.error.HTTPError as e:
                        self.send_error(e.code, f"ERR ROTLD: {e.reason}")
                        return
                else:
                    print(f"[I] SUBDOMENIU {domain} inregistrat exclusiv in MyCloud.")

                #Salvarea rutelor off ramp in mycloud
                db.set(f"origin:{domain}", origin)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"SUCCESS: {domain} mapat catre {origin} pe Off-Ramp.\n".encode())
                return

        elif parsed.path == '/unregister':
            if 'domain' in query and 'original_ip' in query:
                domain = query['domain'][0].lower().strip('.')
                orig_ip = query['original_ip'][0]
                domain_ns = domain + '.'

                if not self.verify_signature(domain, orig_ip, ts_str, client_sig):
                    self.send_error(403, "Invalid signature")
                    return

                saved = db.get(f"origin:{domain}")
                if saved != orig_ip:
                    self.send_error(409, "IP Mismatch")
                    return

                parti_domeniu = domain.split('.')
                is_subdomain = len(parti_domeniu) > 2 or domain.startswith('*.')
                if not is_subdomain:
                    #Daca e Root, scoatem si din rotld si oprim propagarea adreselor POP la req catre acest domeniu
                    try:
                        req_url = f"{ROTLD_URL}/restore_a?domain={domain_ns}&ip={orig_ip}"
                        req = urllib.request.Request(req_url, method='POST')
                        urllib.request.urlopen(req)
                        db.srem("protected_domains", domain_ns)
                        db.delete(f"A:{domain_ns}")
                        db.delete(f"A:*.{domain_ns}")
                        print(f"[I] ROOT DOMAIN {domain} sters din ROTLD.")

                        #Stergem si subdomeniile stocate
                        subdomenii=db.keys(f"origin:*.{domain}")
                        if subdomenii:
                            db.delete(*subdomenii)
                            print(f"[*I] S-au sters {len(subdomenii)} subdomenii pentru {domain}.")
                    except urllib.error.HTTPError as e:
                        self.send_error(e.code, f"ERR ROTLD: {e.reason}")
                        return
                else:
                    print(f"[I] SUBDOMENIU {domain} sters din MyCloud.")
                #Stergem ruta off ramp
                db.delete(f"origin:{domain}")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"SUCCESS: Domeniu sters din MyCloud.")
                return

        self.send_error(400, "Bad Request")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    seed_mycloud()
    threading.Thread(target=control_plane_loop, daemon=True).start()
    server = ThreadedTCPServer(("0.0.0.0", PORT), MyCloudHandler)
    print(f"[I] MyCloud API pornit pe portul {PORT}")
    server.serve_forever()