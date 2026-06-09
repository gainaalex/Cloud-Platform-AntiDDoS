import socket
import matplotlib

matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from dnslib import DNSRecord, QTYPE
from collections import Counter

DNS_IP = "127.0.0.1"
DNS_PORT = 5333
TARGET_DOMAIN = "edu.tuiasi.ro"
NUM_REQUESTS = 10000


def ruleaza_test_dns_lb():
    print("=" * 60)
    print(f"[I] Incep testul de Load Balancing la nivel de DNS...")
    print(f"[I] Trimit {NUM_REQUESTS} cereri catre {DNS_IP}:{DNS_PORT} pentru {TARGET_DOMAIN}")
    print("=" * 60)

    rezultate_primul_ip = []

    for i in range(1, NUM_REQUESTS + 1):
        try:
            # Construim cererea DNS manual
            q = DNSRecord.question(TARGET_DOMAIN)
            pachet = q.pack()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)

            # Trimitem cererea catre Resolver
            sock.sendto(pachet, (DNS_IP, DNS_PORT))

            data, _ = sock.recvfrom(512)
            raspuns = DNSRecord.parse(data)

            # Extragem primul IP din sectiunea Answer
            if raspuns.rr:
                # Luam primul record de tip A
                primul_record = [rr for rr in raspuns.rr if rr.rtype == QTYPE.A]
                if primul_record:
                    primul_ip = str(primul_record[0].rdata)
                    rezultate_primul_ip.append(primul_ip)
                    print(f"[Cerere {i:03d}] -> Primul IP returnat: {primul_ip}")
                else:
                    rezultate_primul_ip.append("Fara inregistrari A")
            else:
                rezultate_primul_ip.append("NXDOMAIN/Empty")

        except Exception as e:
            rezultate_primul_ip.append("Timeout/Eroare")
        finally:
            sock.close()

    genereaza_grafic(rezultate_primul_ip)


def genereaza_grafic(rezultate):
    print("\n[I] Generez graficul de distributie...")

    distributie = Counter(rezultate)

    # Sortam ca sa arate frumos pe grafic
    etichete = sorted(distributie.keys())
    valori = [distributie[k] for k in etichete]

    plt.figure(figsize=(10, 6))
    culori = ['#0d6efd', '#198754', '#ffc107', '#dc3545', '#6f42c1']

    bare = plt.bar(etichete, valori, color=culori[:len(etichete)])

    # Adaugam valorile deasupra fiecarei bare
    for bara in bare:
        inaltime = bara.get_height()
        plt.text(bara.get_x() + bara.get_width() / 2., inaltime + (max(valori) * 0.02),
                 f'{int(inaltime)}',
                 ha='center', va='bottom', fontsize=12, fontweight='bold')

    plt.title('Distributia adreselor POP urilor active in Cloud',
              fontsize=14, pad=15)
    plt.xlabel('IP-ul POP-ului returnat', fontsize=12)
    plt.ylabel('Numar de selectii', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Setam marginea de sus
    if valori:
        plt.ylim(0, max(valori) + (max(valori) * 0.15))

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    ruleaza_test_dns_lb()