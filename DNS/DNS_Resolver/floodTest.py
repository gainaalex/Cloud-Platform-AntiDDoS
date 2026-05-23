import socket
import time
import threading
from dnslib import DNSRecord


RESOLVER_IP = "127.0.0.1"
RESOLVER_PORT = 5333
DOMENIU_TEST = "api.mycloud.ro"


NUMAR_TOTAL_CERERI = 120
THREADS_CONCURENTE = 10


def trimite_cerere_dns(id_cerere):

    try:
        q = DNSRecord.question(DOMENIU_TEST)
        pachet = q.pack()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        timp_start = time.time()
        sock.sendto(pachet, (RESOLVER_IP, RESOLVER_PORT))

        data, _ = sock.recvfrom(512)
        raspuns = DNSRecord.parse(data)

        rcode_name = raspuns.header.rcode
        print(
            f"[Cerere {id_cerere:03d}] -> Status: Succes (RCODE: {rcode_name}) | Timp: {(time.time() - timp_start) * 1000:.1f}ms")

    except socket.timeout:
        print(f"[Cerere {id_cerere:03d}] -> [*] TIMEOUT (Resolverul ne ignora pachetele -> BAN ACTIV!)")
    except Exception as e:
        print(f"[Cerere {id_cerere:03d}] -> [Eroare]: {e}")
    finally:
        sock.close()


def porneste_atac_simulat():
    print("=" * 60)
    print(f"[I:] Pornesc simularea de DNS Flood catre {RESOLVER_IP}:{RESOLVER_PORT}")
    print(f"[I:] Trimit {NUMAR_TOTAL_CERERI} cereri folosind {THREADS_CONCURENTE} thread-uri paralele...")
    print("=" * 60)

    threads = []
    timp_inceput_atac = time.time()

    # Distribuim cererile in mod concurent pe thread-uri
    for i in range(NUMAR_TOTAL_CERERI):
        t = threading.Thread(target=trimite_cerere_dns, args=(i + 1,))
        threads.append(t)
        t.start()

        # Introducem o micro-pauza la pornirea thread-urilor ca sa nu blocam scheduler-ul local al OS-ului
        if len(threads) % THREADS_CONCURENTE == 0:
            time.sleep(0.02)

    # Asteptam ca toate thread-urile sa isi termine executia sau sa dea timeout
    for t in threads:
        t.join()

    durata_totala = time.time() - timp_inceput_atac
    print("=" * 60)
    print(f"[I:] Atacul s-a terminat in {durata_totala:.2f} secunde.")
    print("=" * 60)


if __name__ == "__main__":
    porneste_atac_simulat()