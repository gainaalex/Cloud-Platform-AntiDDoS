import matplotlib
import requests
import matplotlib.pyplot as plt
matplotlib.use('TkAgg')
from collections import Counter
import time

#pentru acest test am dezactivat WAF FLOOD Protection punand parametrii:
#- WAF_FLOOD_WINDOW = 1
#- WAF_FLOOD_MAX_REQS = 500
#- WAF_BAN_TIMEOUT = 1

TARGET_URL = "http://127.0.0.1:8086/static/image.jpg"
HOST_HEADER = "edu.tuiasi.ro"
NUMAR_CERERI = 3000


noduri_waf = []


def ruleaza_test_load_balancing():
    print("=" * 60)
    print(f"[I] Incep testarea de Load Balancing (Round-Robin) catre POP...")
    print(f"[I] URL: {TARGET_URL} | Host: {HOST_HEADER}")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({
        "Host": HOST_HEADER,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    })

    for i in range(1, NUMAR_CERERI + 1):
        try:
            # trimitem cererea catre POP
            response = session.get(TARGET_URL, timeout=2)

            # extragem header-ul custom setat in WAF
            waf_node = response.headers.get('X-WAF-Node', 'Necunoscut/Eroare')
            noduri_waf.append(waf_node)

            print(f"[Cerere {i:02d}] -> Status: {response.status_code} | Procesat de: {waf_node}")

            # micro-pauza pentru a nu declansa eventuale reguli de flood HTTP
            time.sleep(0.05)

        except requests.exceptions.RequestException as e:
            print(f"[Cerere {i:02d}] -> [Eroare de conexiune]: {e}")
            noduri_waf.append("Eroare/Timeout")

    genereaza_grafic_distributie()


def genereaza_grafic_distributie():
    print("\n[I] Generare grafic:")

    distributie = Counter(noduri_waf)

    id_uri_reale = sorted(distributie.keys())

    etichete_noi = []
    for i, id_real in enumerate(id_uri_reale):
        if id_real == "Eroare/Timeout":
            etichete_noi.append("Eroare")
        else:
            etichete_noi.append(f"N{i + 1}")

    valori = [distributie[id_real] for id_real in id_uri_reale]

    plt.figure(figsize=(10, 6))


    bare = plt.bar(etichete_noi, valori, color=['#007bff', '#28a745', '#ffc107', '#dc3545'][:len(etichete_noi)])

    for bara in bare:
        inaltime = bara.get_height()
        plt.text(bara.get_x() + bara.get_width() / 2., inaltime + 0.5,
                 f'{int(inaltime)}',
                 ha='center', va='bottom', fontsize=12, fontweight='bold')

    plt.title('Distributia Cererilor HTTP', fontsize=14, pad=15)
    plt.xlabel('Endpoint-uri WAF Active', fontsize=12)
    plt.ylabel('Numar de cereri procesate', fontsize=12)

    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Setam o marja deasupra celei mai inalte bare pentru estetica
    plt.ylim(0, max(valori) + (max(valori) * 0.2))

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    ruleaza_test_load_balancing()