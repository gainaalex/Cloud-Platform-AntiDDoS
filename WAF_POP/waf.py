import http.server
import socketserver
import sys
import urllib.parse
import re
import redis
import threading
import time
import socket
import os

# waf e pe nivelul 7 in osi
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')

# in industrie sunt importate constant din owasp dar pentru o lucrare academica o sa ma limitez doar la o parte din atacuri si doar la
# cateva moduri in care pot fi modelate de atacator
ATTACK_SIGNATURES = {
    "SQL_INJECTION": re.compile(
        r"(?i)(union.*select|insert.*into|drop\s+table|waitfor\s+delay|sleep\s*\(|information_schema|' OR \d+=\d+|' OR '[a-z]'='[a-z]|--$)"),
    "XSS": re.compile(r"(?i)(<script>|javascript:|onerror=)"),
    "PATH_TRAVERSAL": re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd)")
}


def analyze_request(path, headers, body=""):
    # normalizam URL-ul
    # vezi rfc 3986
    decoded_path = urllib.parse.unquote(path)
    decoded_body = urllib.parse.unquote(body)

    full_payload = decoded_path + " | " + decoded_body

    for attack_type, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(full_payload):
            return False, attack_type

    # 3. Verificam Headerele (ex: un User-Agent falsificat sau malitios) #vezi rfc 3986
    user_agent = headers.get('User-Agent', '')
    for attack_type, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(user_agent):
            return False, f"{attack_type} (in User-Agent)"

    return True, "CLEAN"


class WAFNodeHandler(http.server.BaseHTTPRequestHandler):
    def handle_waf_logic(self, method, body=""):
        client_ip = self.client_address[0]

        is_safe, threat_type = analyze_request(self.path, self.headers, body)

        if not is_safe:
            print(f"[*W] [WAF-BLOCK] Atac respins de la {client_ip} pe portul {PORT}")
            print(f"     Motiv: {threat_type} detectat in -> {self.path}")

            # status http 403(forbidden)
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            error_html = f"<html><body><h1>403 Forbidden</h1><p>Request blocked by WAF.</p><p>Reason: {threat_type}</p></body></html>"
            self.wfile.write(error_html.encode('utf-8'))
            return

        print(f"[*I] [WAF-ALLOW] Trafic validat rutat spre {self.path} (Procesat de WAF-{PORT})")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # aici ar trebui sa facem cererea spre origin server (off ramp) sau spre CDN cache
        # momentan simulam livrarea paginii
        container_id = socket.gethostname()
        success_html = f"<html><body><h2>Cerere valida</h2><p>Procesat de WAF endpoint <b>{container_id}</b></p></body></html>"
        self.wfile.write(success_html.encode('utf-8'))

    def do_GET(self):
        # aici procesez cererile de healh venite de la pop
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
    r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
    my_hostname = socket.gethostname()
    endpoint_url = f"http://{my_hostname}:{PORT}"

    while True:
        try:
            # am pus ttl 10 secunde
            r.set(f"waf_node:{endpoint_url}", "online", ex=10)
        except Exception as e:
            print(f"[*E] Redis error: {e}")
        time.sleep(5)


if __name__ == "__main__":

    threading.Thread(target=register_to_redis, daemon=True).start()

    server = ThreadedTCPServer(("0.0.0.0", PORT), WAFNodeHandler)
    print(f"[*I]: WAF Module pornit pe portul {PORT} (Hostname: {socket.gethostname()})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()