import http.server
import socketserver
import time
import hashlib
import os


PORT = int(os.getenv('PORT', 80))


class OriginHandler(http.server.BaseHTTPRequestHandler):

    def generate_etag(self, content):
        #etag generator
        return '"' + hashlib.md5(content.encode('utf-8')).hexdigest() + '"'

    def do_GET(self):
        print(f"\n[ORIGIN] Cerere GET primita pentru: {self.path}")

        #Caz 1: Cache long ttl (Hit garantat in CDN la urmatoarea cerere)
        if self.path == '/static/image.jpg':
            body = "Simulare continut binar imagine JPEG..."
            etag = self.generate_etag(body)

            #Verificam daca CDN-ul a trimis ETag-ul inapoi (Revalidare)
            if self.headers.get('If-None-Match') == etag:
                print("  -> Trimitem 304 Not Modified")
                self.send_response(304)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header('Content-type', 'image/jpeg')
            self.send_header('Cache-Control', 'public, max-age=5')#pune 60
            self.send_header('ETag', etag)
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
            print("  -> Trimitem 200 OK + Payload complet")

        #Caz 2: Cache short ttl cu Stale-While-Revalidate
        elif self.path == '/api/data':
            #Simulam niste date care se schimba la fiecare 30 de secunde
            time_window = int(time.time() / 60)
            body = f'{{"status": "ok", "time_window": "{time_window}"}}'
            etag = self.generate_etag(body)

            if self.headers.get('If-None-Match') == etag:
                print("  -> Trimitem 304 Not Modified")
                self.send_response(304)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            #Expira in 10 sec, dar CDN-ul poate servi varianta veche inca 60 secunde daca pica serverul
            self.send_header('Cache-Control', 'max-age=10, stale-while-revalidate=60')
            self.send_header('ETag', etag)
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
            print("  -> Trimitem 200 OK + Payload API")

        #Caz 3: Date Confidentiale (WAF/CDN Bypass)
        elif self.path == '/private/dashboard':
            body = "Baza de date cu clienti si parole..."

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            # Directiva no-store OBLIGA logica ta din CDNManager sa nu stocheze nimic in Redis
            self.send_header('Cache-Control', 'private, no-store')
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
            print("  -> Trimitem 200 OK (NO CACHE ALLOWED)")

        #Caz 4: Must-Revalidate (Validare fortata la fiecare 5 secunde)
        elif self.path == '/api/strict':
            body = "Aceste date sunt critice si trebuie confirmate des."
            etag = self.generate_etag(body)

            if self.headers.get('If-None-Match') == etag:
                print("  -> Trimitem 304 Not Modified (Prelungim viata cache-ului)")
                self.send_response(304)
                self.send_header('Cache-Control', 'max-age=5, must-revalidate')
                self.end_headers()
                return

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            # must-revalidate anuleaza regula de 'stale' din CDN-ul tau
            self.send_header('Cache-Control', 'max-age=5, must-revalidate')
            self.send_header('ETag', etag)
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
            print("  -> Trimitem 200 OK (MUST REVALIDATE)")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found pe Origin Server")

    def do_POST(self):
        print(f"\n[ORIGIN] Cerere POST primita pentru: {self.path}")

        #Caz 5: Operatii unsafe (Invalidarea cache-ului in CDN)
        if self.path == '/api/data':
            #Un request POST trebuie sa declanseze functia invalidate_mutations() din CDN
            self.send_response(201)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(
                b'{"status": "created", "msg": "Ai facut un POST, CDN-ul trebuie sa fi sters versiunea cache a /api/data"}')
            print("  -> Trimitem 201 Created (Se asteapta invalidare in CDN)")
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = socketserver.TCPServer(("0.0.0.0", PORT), OriginHandler)
    print(f"[*] Origin Server (Client Simulat) pornit pe portul {PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()