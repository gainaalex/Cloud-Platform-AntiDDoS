import redis
import json
import os
import socket
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

NS_ROLE = os.getenv('NS_ROLE', 'MYCLOUD')

###!!! Functie pentru a transforma numele containerului in IP folosind Docker DNS
def resolve_docker_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"[E:] Nu am putut rezolva host-ul {hostname}: {e}")
        return "127.0.0.1"

def populeaza_redis():
    db.flushdb()


    if NS_ROLE == 'ROOT':
        rotld_hostname = os.getenv('ROTLD_HOSTNAME', 'ns_rotld')
        rotld_ip = resolve_docker_host(rotld_hostname)

        db.set("NS:ro.", json.dumps({"type": "NS", "ips": ["ns.rotld.ro."], "ttl": 86400}))
        db.set("A:ns.rotld.ro.", json.dumps({"type": "A", "ips": [rotld_ip], "ttl": 86400}))
        print(f"[I:] ROOT populat. ns.rotld.ro -> {rotld_ip}")


    elif NS_ROLE == 'ROTLD':
        mycloud_hostname = os.getenv('MYCLOUD_HOSTNAME', 'ns_mycloud')
        mycloud_ip = resolve_docker_host(mycloud_hostname)

        db.set("NS:mycloud.ro.", json.dumps({"type": "NS", "ips": ["ns.mycloud.ro."], "ttl": 120}))
        db.set("NS:edu.tuiasi.ro.", json.dumps({"type": "NS", "ips": ["ns.mycloud.ro."], "ttl": 120}))
        db.set("A:ns.mycloud.ro.", json.dumps({"type": "A", "ips": [mycloud_ip], "ttl": 120}))
        db.set("A:vatafu.ro.", json.dumps({"type": "A", "ips": ["20.20.20.21"], "ttl": 10}))
        print(f"[I:] ROTLD populat. ns.mycloud.ro -> {mycloud_ip}")


    # elif NS_ROLE == 'MYCLOUD':
    #     domenii_protejate = {
    #         "A:edu.tuiasi.ro.": {"type": "A", "ips": ["10.0.0.50", "10.0.0.51"], "ttl": 30},
    #         "A:emag.ro.": {"type": "A", "ips": ["10.0.0.50", "10.0.0.51"], "ttl": 30},
    #         "A:magazin.mycloud.ro.": {"type": "A", "ips": ["10.0.0.100"], "ttl": 300},
    #         "A:api.mycloud.ro.": {"type": "A", "ips": ["10.0.0.200", "10.0.0.201"], "ttl": 30}
    #     }
    #
    #     for domeniu, date in domenii_protejate.items():
    #         db.set(domeniu, json.dumps(date))
    #     print("[I:] MYCLOUD_AUTH populat.")

def get_all_data():
    chei = db.keys('*')
    print("\n" + "=" * 40)
    print(f"[I:] REDIS DB ({NS_ROLE}): ")

    if not chei:
        print("[I:] BD gol")
    else:
        for cheie in chei:
            valoare_json = db.get(cheie)
            valoare = json.loads(valoare_json)
            print(f"[I:] {cheie} -> IP/NS: {valoare['ips']} | TTL: {valoare['ttl']} | Type: {valoare['type']}")
    print("=" * 40 + "\n")

if __name__ == "__main__":
    populeaza_redis()