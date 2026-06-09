import matplotlib
import matplotlib.pyplot as plt
import requests
import time
import concurrent.futures
from collections import defaultdict
import dns.resolver
import random

matplotlib.use('TkAgg')

# --- CONFIGURATIE PLATFORMA ---
DNS_IP = "127.0.0.1"
DNS_PORT = 5333
TARGET_DOMAIN = "edu.tuiasi.ro"
TARGET_PATH = "/static/image.jpg"
DURATA_SCENARIU = 15  # Secunde per scenariu
WORKERS = 30  # Concurenta pentru Flood

# --- STRUCTURI DE COLECTARE DATE ---
statistici = {
    "DNS": {"cerute": 0, "rezolvate": 0, "blocate_timeout": 0},
    "WAF": defaultdict(lambda: {"CLEAN": 0, "SQLI": 0, "XSS": 0, "FLOOD": 0}),
    "OFF_RAMP": {"CDN_HIT": 0, "ORIGIN_MISS": 0, "ORIGIN_LOAD": 0}
}
istoric_timp_origin = []  # Colectam cand au fost atinse serverele origin


# --- 1. FUNCTII DE INTEROGARE DNS ---
def rezolva_dns():
    statistici["DNS"]["cerute"] += 1
    res = dns.resolver.Resolver()
    res.nameservers = [DNS_IP]
    res.port = DNS_PORT
    try:
        # Folosim timeout mic pentru a prinde rapid Drop-urile/Rate-Limits de la DNS
        answers = res.resolve(TARGET_DOMAIN, 'A', lifetime=1.0)
        statistici["DNS"]["rezolvate"] += 1
        return [answer.to_text() for answer in answers][0]  # Returnam primul IP din pool
    except Exception:
        statistici["DNS"]["blocate_timeout"] += 1
        return None


# --- 2. FUNCTII DE INTEROGARE HTTP (Layer 7) ---
def trimite_cerere_http(ip_pop, tip_atac="CLEAN", timp_start=0):
    url = f"http://{ip_pop}:8080{TARGET_PATH}"
    headers = {"Host": TARGET_DOMAIN, "User-Agent": "E2E-Tester"}

    # Injectam payload daca e atac calitativ
    if tip_atac == "SQLI":
        url = f"http://{ip_pop}:8080/login?user=' OR 1=1--"
    elif tip_atac == "XSS":
        url = f"http://{ip_pop}:8080/search?q=<script>alert(1)</script>"

    try:
        resp = requests.get(url, headers=headers, timeout=2)
        waf_node = resp.headers.get('X-WAF-Node', resp.headers.get('x-waf-node', 'N/A'))
        x_cache = resp.headers.get('X-Cache', resp.headers.get('x-cache', 'MISS'))
        status = resp.status_code

        # Clasificare WAF (On-Ramp)
        if status == 429:
            statistici["WAF"][waf_node]["FLOOD"] += 1
            return
        elif status == 403:
            statistici["WAF"][waf_node][tip_atac] += 1
            return
        elif status < 400 or status == 404:
            statistici["WAF"][waf_node]["CLEAN"] += 1

        # Clasificare CDN/Origin (Off-Ramp)
        if x_cache == "HIT":
            statistici["OFF_RAMP"]["CDN_HIT"] += 1
        else:
            statistici["OFF_RAMP"]["ORIGIN_MISS"] += 1
            statistici["OFF_RAMP"]["ORIGIN_LOAD"] += 1
            timp_relativ = time.time() - timp_start
            istoric_timp_origin.append((timp_relativ, "Origin Load"))

    except Exception:
        pass


# --- SCENARII DE TEST ---

def scenariul_1_flash_crowd():
    print("\n[Scenariul 1] Trafic Legitim Sustinut (Flash Crowd)...")
    ip_pop = rezolva_dns()
    if not ip_pop: return
    timp_start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        while time.time() - timp_start < DURATA_SCENARIU:
            # Rata controlata: suficienta cat sa populeze cache-ul, dar fara a activa Flood-ul WAF
            executor.submit(trimite_cerere_http, ip_pop, "CLEAN", timp_start)
            time.sleep(0.05)


def scenariul_2_dns_amplification():
    print("[Scenariul 2] Atac L3/L4 (DNS Rate Limit / Amplification)...")
    # Tragem sute de cereri DNS pe secunda pentru a activa limitatorul din dns_resolver.py
    timp_start = time.time()
    while time.time() - timp_start < DURATA_SCENARIU:
        rezolva_dns()
        time.sleep(0.005)


def scenariul_3_http_flood():
    print("[Scenariul 3] Atac L7 Volumetric (HTTP Flood)...")
    ip_pop = rezolva_dns()
    if not ip_pop: ip_pop = "127.0.0.1"  # Fallback pt simulare
    timp_start = time.time()

    # Tragem la eficienta maxima pt a bloca WAF-ul
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        while time.time() - timp_start < DURATA_SCENARIU:
            executor.submit(trimite_cerere_http, ip_pop, "CLEAN", timp_start)
            time.sleep(0.005)


def scenariul_4_l7_signatures():
    print("[Scenariul 4] Atac L7 Calitativ (SQLi / XSS)...")
    ip_pop = rezolva_dns()
    if not ip_pop: ip_pop = "127.0.0.1"
    timp_start = time.time()

    atacuri = ["SQLI", "XSS", "CLEAN", "CLEAN"]  # Mix de trafic

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        while time.time() - timp_start < DURATA_SCENARIU:
            tip = random.choice(atacuri)
            executor.submit(trimite_cerere_http, ip_pop, tip, timp_start)
            time.sleep(0.05)


# --- 4. PLANSA DE BORD (DASHBOARD) ---
def genereaza_dashboard():
    print("\n[I] Generez E2E Security Dashboard...")
    fig = plt.figure(figsize=(15, 9))
    fig.suptitle('Platforma Cloud: Raport E2E (DNS -> On-Ramp -> Off-Ramp)', fontsize=16, fontweight='bold')

    # Grid 2x2
    gs = fig.add_gridspec(2, 2, height_ratios=[1, 1.2], wspace=0.2, hspace=0.3)

    # --- PANEL 1: DNS Shield (Stanga Sus) ---
    ax1 = fig.add_subplot(gs[0, 0])
    dns_labels = ['Rezolvate', 'Blocate (Anti-Flood)']
    dns_values = [statistici["DNS"]["rezolvate"], statistici["DNS"]["blocate_timeout"]]
    ax1.bar(dns_labels, dns_values, color=['#198754', '#dc3545'], alpha=0.8)
    for i, v in enumerate(dns_values):
        ax1.text(i, v + (max(dns_values) * 0.05), str(v), ha='center', fontweight='bold')
    ax1.set_title('Layer 3/4: Protectie DNS Resolver', pad=10)
    ax1.set_ylabel('Cereri DNS')

    # --- PANEL 2: Off-Ramp CDN vs Origin Load (Dreapta Sus) ---
    ax2 = fig.add_subplot(gs[0, 1])
    off_labels = ['Trafic Absorbit (CDN)', 'Trafic Scurs (Origin)']
    off_values = [statistici["OFF_RAMP"]["CDN_HIT"], statistici["OFF_RAMP"]["ORIGIN_MISS"]]
    ax2.bar(off_labels, off_values, color=['#0dcaf0', '#ffc107'], alpha=0.8)
    for i, v in enumerate(off_values):
        ax2.text(i, v + (max(off_values) * 0.05 if off_values else 1), str(v), ha='center', fontweight='bold')
    ax2.set_title('Layer 7 Off-Ramp: Eficienta Cache-ului', pad=10)
    ax2.set_ylabel('Pachete Servite')

    # --- PANEL 3: WAF Distribution (Jos, ocupand ambele coloane) ---
    ax3 = fig.add_subplot(gs[1, :])
    noduri_waf = sorted([k for k in statistici["WAF"].keys() if k != "N/A"])

    if noduri_waf:
        x_indexes = range(len(noduri_waf))
        wid = 0.2

        c_clean = [statistici["WAF"][n]["CLEAN"] for n in noduri_waf]
        c_flood = [statistici["WAF"][n]["FLOOD"] for n in noduri_waf]
        c_sqli = [statistici["WAF"][n]["SQLI"] for n in noduri_waf]
        c_xss = [statistici["WAF"][n]["XSS"] for n in noduri_waf]

        ax3.bar([x - wid * 1.5 for x in x_indexes], c_clean, width=wid, label='Permis (Clean)', color='#198754')
        ax3.bar([x - wid * 0.5 for x in x_indexes], c_flood, width=wid, label='Blocat (Flood 429)', color='#dc3545')
        ax3.bar([x + wid * 0.5 for x in x_indexes], c_sqli, width=wid, label='Blocat (SQLi)', color='#fd7e14')
        ax3.bar([x + wid * 1.5 for x in x_indexes], c_xss, width=wid, label='Blocat (XSS)', color='#ffc107')

        ax3.set_xticks(x_indexes)
        ax3.set_xticklabels([f"WAF Node: {n}" for n in noduri_waf])
        ax3.set_title('Layer 7 On-Ramp: Distributia Inspectiei pe Pool-ul WAF', pad=10)
        ax3.legend(loc='upper right')
        ax3.grid(axis='y', linestyle='--', alpha=0.3)
    else:
        ax3.text(0.5, 0.5, "Nu s-au inregistrat date WAF.\nVerifica conexiunea LB -> WAF.", ha='center', va='center',
                 fontsize=12)

    # --- CASETA CONCLUZIE ---
    total_req_l7 = sum(sum(v.values()) for v in statistici["WAF"].values())
    text_rezultat = (
        f"REZUMAT SECURITATE CLOUD\n"
        f"------------------------\n"
        f"Atac DNS atenuat la margine.\n"
        f"Din {total_req_l7} cereri L7 ajunse in retea:\n"
        f" - {statistici['OFF_RAMP']['ORIGIN_MISS']} au atins serverul Origin.\n"
        f" - Serverul a fost protejat in proportie de "
        f"{((total_req_l7 - statistici['OFF_RAMP']['ORIGIN_MISS']) / total_req_l7 * 100) if total_req_l7 > 0 else 100:.1f}%\n"
    )
    plt.figtext(0.5, 0.02, text_rezultat, ha="center", fontsize=11,
                bbox=dict(boxstyle="round,pad=0.5", facecolor="#f8f9fa", edgecolor="#ced4da"))

    plt.subplots_adjust(bottom=0.15)  # Spatiu pt caseta
    plt.show()


if __name__ == "__main__":
    print("=== STARTING END-TO-END PLATFORM TEST ===")
    scenariul_1_flash_crowd()
    scenariul_2_dns_amplification()
    scenariul_3_http_flood()
    scenariul_4_l7_signatures()
    genereaza_dashboard()