import redis
import json
import time
import os

# Conexiunea la baza de date DNS
REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
db = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

# Domeniile pe care vrem sa le mapam dinamic catre POP-uri
DOMENII_PROTEJATE = [
    "edu.tuiasi.ro.",
    "api.mycloud.ro.",
    "magazin.mycloud.ro.",
    "emag.ro."
]


def actualizeaza_rute_dns():
    print("[*I] Control Plane pornit. Monitorizez POP-urile active...")

    while True:
        try:
            # 1. Cautam POP-urile active in acest moment
            chei_active = db.keys("heartbeat:POP:*")
            ips_live = [k.split(":")[-1] for k in chei_active]

            # 2. Daca avem POP-uri, actualizam inregistrarile de tip A
            if ips_live:
                for domeniu in DOMENII_PROTEJATE:
                    date_dns = {
                        "type": "A",
                        "ips": ips_live,
                        "ttl": 30  # TTL mic pt ca rutele se pot schimba des
                    }
                    db.set(f"A:{domeniu}", json.dumps(date_dns))
            else:
                # Daca niciun POP nu e activ, putem sterge rutele sau pune un fallback
                for domeniu in DOMENII_PROTEJATE:
                    db.delete(f"A:{domeniu}")

        except Exception as e:
            print(f"[*E] Eroare in Control Plane: {e}")

        # Rulam verificarea la fiecare 5 secunde
        time.sleep(5)


if __name__ == "__main__":
    actualizeaza_rute_dns()