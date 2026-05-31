import matplotlib
import requests
import matplotlib.pyplot as plt
import time
import concurrent.futures
from collections import defaultdict
import numpy as np

matplotlib.use('TkAgg')

CYCLES=50

TARGET_URL = "http://127.0.0.1:8080"
HOST_HEADER = "edu.tuiasi.ro"

# Am mapat exact semnaturile din dictionarul tau ATTACK_SIGNATURES
PAYLOADS = [
    {"type": "CLEAN", "path": "/search?q=carti_programare", "headers": {"User-Agent": "Mozilla/5.0"}},
    {"type": "SQL_INJECTION", "path": "/login?user=admin'+OR+1=1--", "headers": {"User-Agent": "Mozilla/5.0"}},
    {"type": "XSS", "path": "/comment?text=<script>alert(1)</script>", "headers": {"User-Agent": "Mozilla/5.0"}},
    {"type": "PATH_TRAVERSAL", "path": "/../../../../etc/passwd", "headers": {"User-Agent": "Mozilla/5.0"}},
    {"type": "RESERVED_NAMES", "path": "/download/AUX", "headers": {"User-Agent": "Mozilla/5.0"}},
    {"type": "SENSITIVE_PORT", "path": "/proxy:22/", "headers": {"User-Agent": "Mozilla/5.0"}},
    {"type": "KNOWN_SCANNER", "path": "/", "headers": {"User-Agent": "sqlmap/1.6.8.11"}},
]

# Stocam rezultatele in format: { nod_waf: { tip_amenintare: numar_cereri } }
rezultate_waf = defaultdict(lambda: defaultdict(int))
# Set pentru a asigura o legenda curata
tipuri_detectate = set()


def trimite_cerere(session, payload, id_cerere):
    url = f"{TARGET_URL}{payload['path']}"
    headers = {"Host": HOST_HEADER}
    headers.update(payload['headers'])

    try:
        response = session.get(url, headers=headers, timeout=2)

        # Cautam headerul case-insensitive. Daca nu exista sub forma X-WAF-Node,
        # il cautam sub forma x-waf-node, iar daca tot nu e, il marcam Necunoscut.
        waf_node = response.headers.get('X-WAF-Node', response.headers.get('x-waf-node', 'Eroare/Necunoscut'))

        # Daca tot returneaza Necunoscut, afisam TOATE headerele primite pt debugging rapid
        if waf_node == 'Eroare/Necunoscut':
            print(f"[DEBUG] Cererea {id_cerere} a primit headerele: {response.headers}")

        # WAF-ul returneaza 403 pentru trafic malitios si blocheaza request-ul
        if response.status_code == 403:
            rezultate_waf[waf_node][payload["type"]] += 1
            tipuri_detectate.add(payload["type"])
            print(f"[Cerere {id_cerere:03d}] -> {waf_node} a BLOCAT: {payload['type']}")

        # Orice alt cod (200, 304, sau chiar 502 de la Origin) inseamna ca WAF-ul a permis pachetul
        elif response.status_code != 429:
            rezultate_waf[waf_node]["CLEAN"] += 1
            tipuri_detectate.add("CLEAN")
            print(f"[Cerere {id_cerere:03d}] -> {waf_node} a PERMIS: Trafic legitim")

    except requests.exceptions.RequestException:
        pass

def ruleaza_test_semnaturi():
    print("=" * 60)
    print("[I] Incep testarea inspectiei de pachete WAF (Layer 7)...")
    print("[I] Ritm setat sub 50 req/s pentru a nu declansa regula de Flood.")
    print("=" * 60)

    session = requests.Session()
    id_cerere = 0

    # CYCLES numar de cicluri * 7 tipuri de payload
    for ciclu in range(CYCLES):
        for payload in PAYLOADS:
            id_cerere += 1
            trimite_cerere(session, payload, id_cerere)
            # Pauza de 0.03s asigura in jur de 33 cereri/secunda, ramanand "sub radarul" de DDOS
            time.sleep(0.03)

    genereaza_grafic_waf()


def genereaza_grafic_waf():
    print("\n[I] Generez graficul de filtrare WAF (Grouped Bar Chart)...")

    # Eliminam "Eroare/Necunoscut" daca cumva mai apare, luam doar nodurile reale (ex: container_id)
    noduri_reale = sorted([k for k in rezultate_waf.keys() if k != "Eroare/Necunoscut"])

    if not noduri_reale:
        print("[!] Eroare: Nu s-a detectat niciun nod WAF. Asigura-te ca headerele sunt trimise corect.")
        return

    etichete_x = [f"N{i + 1}" for i in range(len(noduri_reale))]

    for i, nod_real in enumerate(noduri_reale):
        print(f"[Mapare Licenta] {nod_real} ---> N{i + 1}")

    ordinea_categoriilor = ["CLEAN", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "RESERVED_NAMES", "SENSITIVE_PORT",
                            "KNOWN_SCANNER"]
    culori = {
        "CLEAN": "#198754",  # Verde
        "SQL_INJECTION": "#dc3545",  # Rosu
        "XSS": "#fd7e14",  # Portocaliu
        "PATH_TRAVERSAL": "#ffc107",  # Galben
        "RESERVED_NAMES": "#6f42c1",  # Mov
        "SENSITIVE_PORT": "#d63384",  # Roz
        "KNOWN_SCANNER": "#0dcaf0"  # Cyan
    }

    categorii_prezente = [cat for cat in ordinea_categoriilor if cat in tipuri_detectate]

    numar_noduri = len(noduri_reale)
    numar_categorii = len(categorii_prezente)

    # Setari pentru axa X
    pozitii_de_baza_x = np.arange(numar_noduri)
    latime_bara = 0.12  # Bare subtiri pentru a incapea in grup

    plt.figure(figsize=(14, 7))

    for index, categorie in enumerate(categorii_prezente):
        # Extragem valorile pentru categoria curenta
        valori = [rezultate_waf[nod].get(categorie, 0) for nod in noduri_reale]

        # Calculam decalajul (offset-ul) barei pentru a o grupa corect
        offset = (index - numar_categorii / 2) * latime_bara + latime_bara / 2
        pozitii_bare_curente = pozitii_de_baza_x + offset

        bare = plt.bar(pozitii_bare_curente, valori, width=latime_bara,
                       label=categorie, color=culori[categorie], alpha=0.9, edgecolor='white', linewidth=0.5)

        # Adaugam label cu numarul fix deasupra barei
        for bara in bare:
            inaltime = bara.get_height()
            if inaltime > 0:
                plt.text(bara.get_x() + bara.get_width() / 2., inaltime + 0.1,
                         f'{int(inaltime)}',
                         ha='center', va='bottom', fontsize=9, fontweight='bold', color='#333333')

    # --- CALCUL STATISTICI ---
    total_cereri = sum(sum(atacuri.values()) for atacuri in rezultate_waf.values())
    total_clean = sum(rezultate_waf[n].get("CLEAN", 0) for n in noduri_reale)
    total_atacuri = total_cereri - total_clean
    rata_blocare = (total_atacuri / (6*CYCLES) * 100) if total_cereri > 0 else 0

    text_statistici = (
        f"STATISTICI DE SECURITATE (WAF Pool):\n"
        f"------------------------------------\n"
        f"Pachete inspectate: {total_cereri}\n"
        f"Trafic legitim permis: {total_clean}\n"
        f"Atacuri blocate: {total_atacuri}\n\n"
        f" => Rata de blocare: {rata_blocare:.1f}%\n"
    )

    # --- SETARI VIZUALE AXE ---
    plt.xticks(pozitii_de_baza_x, etichete_x, fontsize=12, fontweight='bold')
    plt.title('Distributia Atacurilor In functie de tip per Nod WAF', fontsize=15, pad=20)
    plt.xlabel('Endpoint-uri WAF Active', fontsize=13)
    plt.ylabel('Numar de cereri procesate', fontsize=13)

    # Margine de siguranta pe axa Y ca sa nu taie cifrele
    if total_cereri > 0:
        plt.ylim(0, max(max(atacuri.values()) for atacuri in rezultate_waf.values()) * 1.15)

    plt.grid(axis='y', linestyle='--', alpha=0.5)

    # Box-ul cu statistici (dreapta sus)
    box_props = dict(boxstyle='round', facecolor='#ffffff', alpha=0.95, edgecolor='#ced4da')
    # Pozitionare in afara graficului, sub legenda din dreapta
    plt.text(1.02, 0.45, text_statistici, transform=plt.gca().transAxes, fontsize=11,
             verticalalignment='top', horizontalalignment='left', bbox=box_props, family='monospace')
    # Legenda (mutata afara, stanga sus)
    plt.legend(title="Legenda grafic", loc='upper left', bbox_to_anchor=(1.02, 1), borderaxespad=0.)

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    ruleaza_test_semnaturi()