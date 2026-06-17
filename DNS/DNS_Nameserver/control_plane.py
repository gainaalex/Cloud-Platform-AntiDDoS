import redis
import json
import time
import os

REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
db = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

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
            chei_active = db.keys("heartbeat:POP:*")
            ips_live = [k.split(":")[-1] for k in chei_active]

            if ips_live:
                for domeniu in DOMENII_PROTEJATE:
                    date_dns = {
                        "type": "A",
                        "ips": ips_live,
                        "ttl": 30
                    }
                    db.set(f"A:{domeniu}", json.dumps(date_dns))
            else:
                for domeniu in DOMENII_PROTEJATE:
                    db.delete(f"A:{domeniu}")

        except Exception as e:
            print(f"[*E] Eroare in Control Plane: {e}")

        time.sleep(5)


if __name__ == "__main__":
    actualizeaza_rute_dns()