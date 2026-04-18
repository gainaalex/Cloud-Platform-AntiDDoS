import http.server
import socketserver
import time
import urllib.request
import threading
import os
import redis

# Acest POP e un load balancer ce va distribui catre endpoints (serverele de WAF)
LB_IP = os.getenv('POP_IP', '0.0.0.0')
LB_PORT = int(os.getenv('POP_PORT', 8080))
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')


class LoadBalancerCore:
    def __init__(self):
        self.r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
        self.endpoints = []
        self.active_endpoints = []
        self.lock = threading.Lock()

        self.hc_thread = threading.Thread(target=self.health_check, daemon=True)
        self.hc_thread.start()

    def health_check(self):
        while True:
            # facem discovery pe nodurile gasite de redis
            try:
                keys = self.r.keys("waf_node:*")
                self.endpoints = [k.replace("waf_node:", "") for k in keys]
            except Exception as e:
                print(f"[*E] Redis discovery failed: {e}")
                self.endpoints = []

            healthy_endpoints = []
            unhealthy_endpoints = []

            # facem health check pe cele gasite
            for endpoint in self.endpoints:
                try:
                    url = f"{endpoint}/health"
                    req = urllib.request.Request(url, method='GET')
                    with urllib.request.urlopen(req, timeout=2) as response:
                        if response.status == 200:
                            healthy_endpoints.append(endpoint)
                except Exception as e:
                    print(f"[*W]:Endpoint {endpoint} marked as unhealthy due to this err: {e}")
                    unhealthy_endpoints.append(endpoint)
                    pass

            with self.lock:
                new_list = []
                # pt a pastra totusi ordinea in care a ajuns ca urmare a round robin executat pe parcurs
                for endpoint in self.active_endpoints:
                    if endpoint in healthy_endpoints:
                        new_list.append(endpoint)

                # adaug si nodurile care s-au reparat intre timp
                for endpoint in self.endpoints:
                    if endpoint not in new_list and endpoint not in unhealthy_endpoints:
                        new_list.append(endpoint)
                        print(f"[*I][WAF_LIST: UPDATED] endpoint {endpoint} marked as healthy")

                self.active_endpoints = new_list

            time.sleep(5)

    def get_next_endpoint(self):
        # round robin pt distributia sarcinilor intre WAF urile **active**
        with self.lock:
            if not self.active_endpoints:
                return None

            endpoint = self.active_endpoints.pop(0)
            self.active_endpoints.append(endpoint)

            return endpoint


lb_core = LoadBalancerCore()


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        client_ip = self.client_address[0]

        target_endpoint = lb_core.get_next_endpoint()
        print("\n--------------------new transaction-----------------------------------\n")
        if not target_endpoint:
            self.send_error(503, "[*E] Eroare in WAF_POP: Niciun endpoint WAF disponibil.")
            return

        target_url = f"{target_endpoint}{self.path}"

        print(f"[I*][ON-RAMP] Trafic de la {client_ip} -> Rutat catre {target_endpoint} (Metoda: {method})")

        try:
            req = urllib.request.Request(target_url, method=method)

            for key, value in self.headers.items():
                req.add_header(key, value)

            with urllib.request.urlopen(req, timeout=5) as response:
                response_body = response.read()
                status_code = response.getcode()

                self.send_response(status_code)
                for key, value in response.info().items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response_body)

        except urllib.error.HTTPError as e:
            # pentru eventualele erori Http ridicate ulterior
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(e.read())
            print(f"[*W]:[WAF-BLOCK] Endpoint-ul a blocat cererea cu status {e.code}")

        except urllib.error.URLError as e:
            # daca url e outdated sau daca endpoint ul e mort
            print(f"[*W]:[LB-ERROR] Endpoint-ul {target_endpoint} nu raspunde: {e.reason}")
            self.send_error(502, "INTERNAL ERR:WAF endpoint communication failed.")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadedTCPServer((LB_IP, LB_PORT), ProxyHTTPRequestHandler)
    print(f"[*I]: POP Load Balancer (On Ramp) pornit pe {LB_IP}:{LB_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()