import redis
import os

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
r = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)


def setup_origin_routes():
    r.flushdb()
    rute_clienti = {
        "api.mycloud.ro": "172.20.0.10:80",
        "magazin.mycloud.ro": "172.20.0.11:80",
        "edu.tuiasi.ro": "172.20.0.12:8080"
    }

    print("=" * 50)
    print("[*I] [POP SETUP] Incarcare rute Origin in Redis...")

    for domeniu, adresa_origine in rute_clienti.items():
        cheie_redis = f"origin:{domeniu}"
        r.set(cheie_redis, adresa_origine)
        print(f" [+] Mapare adaugata: {domeniu} ---> {adresa_origine}")

    print("[*I] [POP SETUP] Rutele au fost incarcate cu succes!")
    print("=" * 50)


if __name__ == "__main__":
    setup_origin_routes()