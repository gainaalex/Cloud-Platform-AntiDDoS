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

#Folosit pentru a gasi adresa IP alocata la nivelul retelei Docker
def resolve_docker_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"[E:] Nu am putut rezolva host-ul {hostname}: {e}")
        return "127.0.0.1"


#Logica de populare a bazei de date cu domenii

#Aici e logica doar pentru Root si ROTLD, control_plane se
#ocupa de popularea si transmiterea domeniilor din MyCloud
def populeaza_redis():
    db.flushdb()

    if NS_ROLE == 'ROOT':
        rotld_hostname = os.getenv('ROTLD_HOSTNAME', 'ns_rotld')
        rotld_ip = resolve_docker_host(rotld_hostname)

        db.set("NS:ro.", json.dumps({"type": "NS", "ips": ["ns.rotld.ro."], "ttl": 86400}))
        db.set("A:ns.rotld.ro.", json.dumps({"type": "A", "ips": [rotld_ip], "ttl": 86400}))
        print(f"[I:] ROOT populat. ns.rotld.ro -> {rotld_ip}")


    elif NS_ROLE == 'ROTLD':

        mycloud_hostname = os.getenv('MYCLOUD_HOSTNAME', 'ns.mycloud.ro')
        mycloud_ip = resolve_docker_host(mycloud_hostname)

        db.set("NS:emag.ro.", json.dumps({"type": "NS", "ips": ["ns.mycloud.ro."], "ttl": 120}))
        db.set("NS:mycloud.ro.", json.dumps({"type": "NS", "ips": ["ns.mycloud.ro."], "ttl": 120}))
        db.set("NS:tuiasi.ro.", json.dumps({"type": "NS", "ips": ["ns.mycloud.ro."], "ttl": 120}))
        db.set("A:ns.mycloud.ro.", json.dumps({"type": "A", "ips": [mycloud_ip], "ttl": 120}))
        db.set("A:vatafu.ro.", json.dumps({"type": "A", "ips": ["20.20.20.21"], "ttl": 10}))
        db.set("A:digi.ro.", json.dumps({"type": "A", "ips": ["80.17.101.33"], "ttl": 10}))
        print(f"[I:] ROTLD populat. ns.mycloud.ro -> {mycloud_ip}")


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