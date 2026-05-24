import urllib.request
import urllib.error
import time

TARGET_URL = "http://127.0.0.1:8080/static/image.jpg"
HEADERS = {
    "Host": "edu.tuiasi.ro",
    #trebuie agent ca sa nu pice testul waf pt user-agent
    "User-Agent": "Python-Flood-Test/1.0"
}
NUM_REQUESTS = 100

print(f"[*] Incepem testul de HTTP Flood...")
print(f"[*] Target: {TARGET_URL}")
print(f"[*] Header Host: {HEADERS['Host']}")
print("-" * 50)

start_time = time.time()
sucess=0
for i in range(1, NUM_REQUESTS + 1):
    req = urllib.request.Request(TARGET_URL, headers=HEADERS)

    try:
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            sucess+=1
            print(f"[Req {i:02d}] Status: {status} OK")

    except urllib.error.HTTPError as e:
        print(f"[Req {i:02d}] Status: {e.code} BLOCKED ({e.reason})")

    except urllib.error.URLError as e:
        print(f"[Req {i:02d}] EROARE DE CONEXIUNE: {e.reason}")

end_time = time.time()
print("-" * 50)
print(f"[*] Test finalizat. S-au trimis {NUM_REQUESTS} request-uri in {end_time - start_time:.2f} secunde.\nCereri ce au trecut de filtru:{sucess}/{NUM_REQUESTS}")