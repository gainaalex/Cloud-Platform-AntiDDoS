import redis
import json
import os
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
def populeaza_redis():
    domenii_protejate = {
        "edu.tuiasi.ro.": {"type": "A", "ip": "10.0.0.50", "ttl": 300},
        "masini-ieftine.ro.": {"type": "A", "ip": "10.0.0.50", "ttl": 300},
        "digi.ro.": {"type": "A", "ip": "10.0.0.50", "ttl": 300}
    }

    for domeniu, date in domenii_protejate.items():
        db.set(domeniu, json.dumps(date))
        print(f"[I:] NS: {domeniu} -> {date['ip']}")

def get_all_data():
    chei = db.keys('*')

    print("\n" + "=" * 40)
    print("[I:] REDIS DB: ")

    if not chei:
        print("[I:] BD goal")
    else:
        for cheie in chei:
            valoare_json = db.get(cheie)

            valoare = json.loads(valoare_json)

            print(f"[I:] {cheie} ->\t\t\tIP: {valoare['ip']} | TTL: {valoare['ttl']} | Type: {valoare['type']}")

    print("=" * 40 + "\n")


if __name__ == "__main__":
    populeaza_redis()