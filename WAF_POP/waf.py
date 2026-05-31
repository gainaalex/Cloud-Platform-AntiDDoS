import http.server
import socketserver
import sys
import urllib.parse
import urllib.request
import re
import redis
import threading
import time
import socket
import os
import json

from cdn_logic import CDNManager

# Parametrii WAF flood prevention
WAF_FLOOD_WINDOW = int(os.getenv('WAF_FLOOD_WINDOW', 1))
WAF_FLOOD_MAX_REQS = int(os.getenv('WAF_FLOOD_MAX_REQS', 50))
WAF_BAN_TIMEOUT = int(os.getenv('WAF_BAN_TIMEOUT', 120))


# waf e pe nivelul 7 in osi
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')

redis_client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

cdn_manager = CDNManager(redis_client=redis_client)

# in industrie sunt importate constant din owasp dar pentru o lucrare academica o sa ma limitez doar la o parte din atacuri si doar la
# cateva moduri in care pot fi modelate de atacator
ATTACK_SIGNATURES = {
    "SQL_INJECTION": re.compile(
        r"(?i)(union.*select|insert.*into|drop\s+table|waitfor\s+delay|sleep\s*\(|information_schema|' OR \d+=\d+|' OR '[a-z]'='[a-z]|--$)"),
    "XSS": re.compile(r"(?i)(<script>|javascript:|onerror=)"),
    "PATH_TRAVERSAL": re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|\x00)"),#din RFC 3986 sectiunea 7
    "RESERVED_NAMES": re.compile(r"(?i)\b(AUX|PRN|CON|LPT[1-9]|COM[1-9])\b"),#din RFC 3986 sectiunea 7
    "SENSITIVE_PORT_ACCESS": re.compile(r":([0-9]{1,3}|102[0-3])($|/|\?)"),#din RFC 3986 sectiunea 7,
    "KNOWN_SCANNER": re.compile(r"(?i)(sqlmap|nikto|wpscan|dirbuster|nmap|zgrab|masscan|python-requests|go-http-client)")#CWE-20
}


def client_is_rate_limited(client_ip):
    if redis_client.get(f"ban:{client_ip}"):
        return True

    key = f"rate_limit:{client_ip}"
    try:
        pipe = redis_client.pipeline()
        pipe.incr(key)#current_request
        pipe.ttl(key)#ttl_curent
        rezultate_pipe = pipe.execute()

        current_request = rezultate_pipe[0]
        ttl_curent = rezultate_pipe[1]

        if current_request == 1 or ttl_curent == -1:
            redis_client.expire(key, WAF_FLOOD_WINDOW)

        if current_request > WAF_FLOOD_MAX_REQS:
            print(f"[*W] [HTTP FLOOD DETECTED] IP:{client_ip} a depasit limita de {WAF_FLOOD_MAX_REQS} req/{WAF_FLOOD_WINDOW}seconds")

            redis_client.set(f"ban:{client_ip}", 1, ex=WAF_BAN_TIMEOUT)
            redis_client.delete(key)
            return True

    except Exception as e:
        print(f"[*E] Redis RateLimit Err: {e}")

    return False


def analyze_request(path, headers, body=""):
    # normalizam=decodarea din percent-encode URL-ul
    # vezi rfc 3986

    #print(f"!!!!!path: {path}",flush=True)
    decoded_path = urllib.parse.unquote_plus(path)
    decoded_body = urllib.parse.unquote_plus(body)

    full_payload = decoded_path + " | " + decoded_body

    for attack_type, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(full_payload):
            return False, attack_type

    # verif user-agent header #vezi rfc 3986 si rfc 9110
    user_agent = headers.get('User-Agent', '')
    if not user_agent:#AICI E DE INTREBAT, STANDARDUL ZICE CA USER SHOULD SEND THIS (RFC 9110 S10.1.5)
        return False, "MISSING_USER_AGENT"
    print(f"User-agent:{user_agent}", flush=True)
    for attack_type, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(user_agent):
            return False, f"{attack_type} (in User-Agent)"

    return True, "CLEAN"


class WAFNodeHandler(http.server.BaseHTTPRequestHandler):
    def handle_waf_logic(self, method, body=""):
        xff = self.headers.get('X-Forwarded-For')
        client_ip = xff.split(',')[-1].strip() if xff else self.client_address[0]

        host_header = self.headers.get('Host','').lower()

        print(f"[*I] WAF a primit o cerere pt:{host_header}{self.path}", flush=True)

        # 1) verificam posibil DDOS FLOOD
        if client_is_rate_limited(client_ip):
            print(f"[*W] [RATE-LIMIT] IP {client_ip} blocat (Flood detected)")
            self.send_response(429)
            self.send_header('Content-type', 'text/html')
            #-----------------------------------------------------------------------------------------------------------------------------------
            #asta e pentru testul de flood pe waf
            self.send_header('X-WAF-Node', socket.gethostname())
            # -----------------------------------------------------------------------------------------------------------------------------------
            self.end_headers()
            self.wfile.write(b"<h1>429 Too Many Requests</h1><p>DDoS protection detected suspicios number of requests from you</p>")
            return

        # 2) WAF verifica continutul cererii
        is_safe, threat_type = analyze_request(self.path, self.headers, body)

        if not is_safe:
            print(f"[*W] [WAF-BLOCK] Atac respins de la {client_ip} pe portul {PORT}")
            print(f"     Motiv: {threat_type} detectat in -> {self.path}")

            # status http 403(forbidden)
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            #-----------------------------------------------------------------------------------------------------------------------------------
            #asta am adaugat pentru testul de signatures
            self.send_header('X-WAF-Node', socket.gethostname())
            # -----------------------------------------------------------------------------------------------------------------------------------
            self.end_headers()
            error_html = f"<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF.</p><p>Reason: {threat_type}</p></body></html>"
            self.wfile.write(error_html.encode('utf-8'))
            return

        print(f"[*I] [WAF-ALLOW] Trafic validat rutat spre {self.path} (Procesat de WAF-{PORT})")

        #logica fara CDN:
        #--------------------------------------------------------------------------------------------------------------------------
        # self.send_response(200)
        # self.send_header('Content-type', 'text/html')
        # self.end_headers()
        #
        # # aici ar trebui sa facem cererea spre origin server (off ramp) sau spre CDN cache
        # # momentan simulam livrarea paginii
        # container_id = socket.gethostname()
        # success_html = f"<html><body><h2>Cerere valida</h2><p>Procesat de WAF endpoint <b>{container_id}</b></p></body></html>"
        # self.wfile.write(success_html.encode('utf-8'))
        # --------------------------------------------------------------------------------------------------------------------------

        #logica cu CDN
        origin_address=redis_client.get(f"origin:{host_header}")
        if not origin_address:
            print(f"[*E] [ROUTING] Domeniul cerut {host_header} nu e resolved in myCloud Network")
            self.send_error(502,f"Bad Gateway: Domeniul {host_header} nu e resolved in myCloud Network")
            return

        base_key,vary_sig=cdn_manager.get_redis_keys(host_header,PORT,self.path,self.headers)

        cached_data_json=redis_client.hget(base_key,vary_sig)
        #DACA Exista un match in BD
        if cached_data_json:
            cached_data=json.loads(cached_data_json)

            #aici verificam daca (bineinteles site ul suporta acest tip de validare prin ETag)
            if cdn_manager.validate_client_request(self.headers, cached_data):
                self.send_response(304)
                for k,v in cached_data.get('headers', {}).items():
                    self.send_header(k, v)
                # --------------------------------------------------------------------------------------------
                # pt round robin test
                self.send_header('X-WAF-Node', socket.gethostname())
                # --------------------------------------------------------------------------------------------
                #---------------------------------------------------------------------------------------------
                #pt testul de ddos flood pe http
                self.send_header('X-Cache', 'HIT')
                # ---------------------------------------------------------------------------------------------
                self.end_headers()
                print(f"[*I] [CDN-HIT] Validare cu ETag reusita (ReturnCODE:304)")
                return

            age = time.time() - cached_data.get('stored_at', 0)
            if age < cached_data.get('freshness_ttl', 0) and not cached_data.get('global_no_cache'):
                self.send_response(cached_data.get('status',200))
                for k,v in cached_data.get('headers', {}).items():
                    self.send_header(k, v)

                # --------------------------------------------------------------------------------------------
                # pt round robin test
                self.send_header('X-WAF-Node', socket.gethostname())
                # --------------------------------------------------------------------------------------------
                # ---------------------------------------------------------------------------------------------
                # pt testul de ddos flood pe http
                self.send_header('X-Cache', 'HIT')
                # ---------------------------------------------------------------------------------------------

                self.end_headers()

                self.wfile.write(cached_data.get('body','').encode('utf-8'))
                print(f"[*I] [CDN-HIT] Resursa livrata din cache")
                return

        #DACA nu exista match in BD pentru corpul cererii
        print(f"[*I] [CDN-MISS] Interogam Origin server {origin_address}")
        origin_url=f"http://{origin_address}{self.path}"

        try:
            body_bytes=body.encode('utf-8') if body else None
            req_origin=urllib.request.Request(origin_url,data=body_bytes,method=method)
            for k,v in self.headers.items():
                if k.lower() not in ['host']:
                    req_origin.add_header(k, v)

            req_origin.add_header('X-Forwarded-For',client_ip)

            #pt revalidare cu ETAG
            if cached_data_json:
                cache_vechi = json.loads(cached_data_json)
                etag_vechi = cache_vechi.get('headers', {}).get('ETag')
                if etag_vechi:
                    req_origin.add_header('If-None-Match', etag_vechi)

            with urllib.request.urlopen(req_origin, timeout=5) as response:
                resp_body_bytes=response.read()
                resp_status_code=response.getcode()
                resp_headers_dict=dict(response.info().items())

                #daca origin server returneaza cod 304, acctulizam ttl in cache
                if resp_status_code==304 and cached_data_json:
                    cached_data=json.loads(cached_data_json)
                    cdn_manager.freshen_cache(host_header,PORT,self.path,self.headers,cached_data,resp_headers_dict)

                    self.send_response(200)
                    for k,v in cached_data.get('headers', {}).items():
                        self.send_header(k, v)

                    # --------------------------------------------------------------------------------------------
                    # pt round robin test
                    self.send_header('X-WAF-Node', socket.gethostname())
                    # --------------------------------------------------------------------------------------------
                    # ---------------------------------------------------------------------------------------------
                    # pt testul de ddos flood pe http
                    self.send_header('X-Cache', 'MISS')
                    # ---------------------------------------------------------------------------------------------

                    self.end_headers()
                    self.wfile.write(cached_data.get('body','').encode('utf-8'))
                    return

            # daca cererea e un post / delete facem invalidare de date
            cdn_manager.invalidate_mutations(method,host_header,PORT,self.path,resp_status_code)

            #daca resursa e cacheable, o stocam
            if cdn_manager.is_cacheable(method,self.headers,resp_status_code,resp_headers_dict):
                cdn_manager.store_response(host_header,PORT,self.path,self.headers,resp_status_code,resp_headers_dict,resp_body_bytes.decode('utf-8',errors='ignore'))

            self.send_response(resp_status_code)
            for k,v in resp_headers_dict.items():
                self.send_header(k, v)
            #--------------------------------------------------------------------------------------------
            #pt round robin test
            self.send_header('X-WAF-Node', socket.gethostname())
            #--------------------------------------------------------------------------------------------
            self.end_headers()
            self.wfile.write(resp_body_bytes)

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            #asta am adaugat pentru testul de signatures
            self.send_header('X-WAF-Node', socket.gethostname())
            # --------------------------------------------------------------------------------------------

            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            print(f"[*E] [OFF-RAMP] err de comunicare cu origin server in tranzactia cu {origin_url}: {e}")
            self.send_error(502,"Bad Gateway: Origin server not responding")



    def do_GET(self):
        # aici procesez cererile de health venite de la pop
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if self.path == '/crash':
            print(f"[*F] CRASH INDUS MANUAL pe {socket.gethostname()}! Container crashed",flush=True)
            #500 internal server err
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Crash initiated")
            #sys.exit(1) #nu merge pe multi thread nush dc
            os._exit(1)

        self.handle_waf_logic("GET")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_body = ""

        if content_length > 0:
            post_body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        self.handle_waf_logic("POST", post_body)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def register_to_redis():
    my_hostname = socket.gethostname()
    endpoint_url = f"http://{my_hostname}:{PORT}"

    while True:
        try:
            # am pus ttl 10 secunde
            redis_client.set(f"waf_node:{endpoint_url}", "online", ex=10)
        except Exception as e:
            print(f"[*E] Redis error: {e}")
        time.sleep(5)


if __name__ == "__main__":

    threading.Thread(target=register_to_redis, daemon=True).start()

    server = ThreadedTCPServer(("0.0.0.0", PORT), WAFNodeHandler)
    print(f"[*I]: WAF Module pornit pe portul {PORT} (Hostname: {socket.gethostname()})")
    print(f"[*I]: [DDOS PARAMS] WAF_FLOOD_WINDOW={WAF_FLOOD_WINDOW} WAF_FLOOD_MAX_REQS={WAF_FLOOD_MAX_REQS} WAF_BAN_TIMEOUT={WAF_BAN_TIMEOUT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()