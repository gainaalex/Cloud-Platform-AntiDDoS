import http.server
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081


class WAFMockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"OK")
            return

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        html_response = f"<html><body><h2>Trafic procesat de WAF Endpoint pe portul {PORT}</h2></body></html>"
        self.wfile.write(html_response.encode('utf-8'))

        print(f"[*I] Trafic rutat cu succes catre WAF-{PORT} pentru ruta: {self.path}")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadedTCPServer(("0.0.0.0", PORT), WAFMockHandler)
    print(f"[*I]: WAF Mock Endpoint a pornit si asculta pe portul {PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print(f"\n[*I]: WAF {PORT} -closed-")