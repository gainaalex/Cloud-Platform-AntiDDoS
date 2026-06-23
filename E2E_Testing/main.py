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
TTL_TARGET=5
DURATA_SCENARIU = 25
WORKERS = 40

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


def trimite_cerere_http(ip_pop, tip_atac="CLEAN", timp_start=0):
    # Setam fizic adresa laptopului si portul pe care ai deschis POP-ul Iasi (sau pune 8086 pt Timis)
    HOST_IP = "127.0.0.1"
    HOST_PORT = "8086"

    url = f"http://{HOST_IP}:{HOST_PORT}{TARGET_PATH}"
    headers = {"Host": TARGET_DOMAIN, "User-Agent": "E2E-Tester"}

    # Injectam payload daca e atac calitativ
    if tip_atac == "SQLI":
        url = f"http://{HOST_IP}:{HOST_PORT}/login?user=' OR 1=1--"
    elif tip_atac == "XSS":
        url = f"http://{HOST_IP}:{HOST_PORT}/search?q=<script>alert(1)</script>"

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

    except Exception as e:
        # DACA PICA CEVA, VEZI DIRECT IN TERMINAL DE CE
        print(f"[*E] Eroare la trimiterea cererii: {e}")


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
    timp_start = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        while time.time() - timp_start < DURATA_SCENARIU:
            executor.submit(rezolva_dns)
            time.sleep(0.005)

    time.sleep(1)


def scenariul_3_http_flood():
    print("[Scenariul 3] Atac L7 Volumetric (HTTP Flood)...")
    ip_pop = rezolva_dns()
    if not ip_pop: ip_pop = "127.0.0.1"  # Fallback pt simulare
    timp_start = time.time()

    # Tragem la eficienta maxima pt a bloca WAF-ul
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        while time.time() - timp_start < DURATA_SCENARIU:
            executor.submit(trimite_cerere_http, ip_pop, "CLEAN", timp_start)
            time.sleep(0.01)


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
            time.sleep(0.1)


def genereaza_dashboard():
    print("\n[I] Generez E2E Security Dashboard...")
    fig = plt.figure(figsize=(15, 9))
    fig.suptitle('Platforma Cloud: Raport E2E (DNS -> On-Ramp -> Off-Ramp)', fontsize=16, fontweight='bold')

    # Grid 2x2
    gs = fig.add_gridspec(2, 2, height_ratios=[1, 1.3], wspace=0.2, hspace=0.4)

    # --- CALCUL STATISTICI PREALABILE ---
    total_clean = sum(v["CLEAN"] for v in statistici["WAF"].values())
    total_flood = sum(v["FLOOD"] for v in statistici["WAF"].values())
    total_sqli = sum(v["SQLI"] for v in statistici["WAF"].values())
    total_xss = sum(v["XSS"] for v in statistici["WAF"].values())

    total_req_l7 = total_clean + total_flood + total_sqli + total_xss
    total_blocate = total_flood + total_sqli + total_xss

    procent_protectie = 100.0
    if total_req_l7 > 0:
        procent_protectie = ((total_req_l7 - statistici['OFF_RAMP']['ORIGIN_MISS']) / total_req_l7) * 100

    ax1 = fig.add_subplot(gs[0, 0])
    dns_labels = ['Rezolvate', 'Blocate (Anti-Flood)']
    dns_values = [statistici["DNS"]["rezolvate"], statistici["DNS"]["blocate_timeout"]]
    total_dns = sum(dns_values)

    ax1.bar(dns_labels, dns_values, color=['#198754', '#dc3545'], alpha=0.8)
    for i, v in enumerate(dns_values):
        ax1.text(i, v + (max(dns_values) * 0.05 if max(dns_values) > 0 else 1), str(v), ha='center', fontweight='bold')

    titlu_dns = f"Layer 3/4: Protectie DNS Resolver\n[Scenariul 2: DNS Amplification | Durata: {DURATA_SCENARIU}s | Trafic total: {total_dns}]"
    ax1.set_title(titlu_dns, pad=10, fontsize=11)
    ax1.set_ylabel('Cereri DNS')

    ax2 = fig.add_subplot(gs[0, 1])
    off_labels = ['Respinse (WAF)', 'Absorbite de CDN', 'Forward la Origin Server']
    off_values = [total_blocate, statistici["OFF_RAMP"]["CDN_HIT"], statistici["OFF_RAMP"]["ORIGIN_MISS"]]

    ax2.bar(off_labels, off_values, color=['#dc3545', '#0dcaf0', '#ffc107'], alpha=0.8)
    for i, v in enumerate(off_values):
        ax2.text(i, v + (max(off_values) * 0.05 if max(off_values) > 0 else 1), str(v), ha='center', fontweight='bold')

    titlu_off = f"Layer 7 Pipeline: On-Ramp WAF -> Off-Ramp CDN\n[Scenariile 1, 3, 4 | Trafic total: {total_req_l7}]"
    ax2.set_title(titlu_off, pad=10, fontsize=11)
    ax2.set_ylabel('Pachete Tranzactionate')

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

        titlu_waf = f"Layer 7 On-Ramp: Distributia Inspectiei pe Pool-ul WAF\n[Scenariile 3 & 4: HTTP Flood + SQLi/XSS | Durata test: {DURATA_SCENARIU * 2}s | Pachete inspectate: {total_req_l7}]"
        ax3.set_title(titlu_waf, pad=10, fontsize=11)

        ax3.legend(loc='upper right')
        ax3.grid(axis='y', linestyle='--', alpha=0.3)
    else:
        ax3.text(0.5, 0.5, "Nu s-au inregistrat date WAF.\nVerifica conexiunea LB -> WAF.", ha='center', va='center',
                 fontsize=12)

    text_rezultat = (
        f"REZUMAT TESTE E2E (Timp total executie: {DURATA_SCENARIU * 4}s)\n"
        f"--------------------------------------------------\n"
        f"Resursa accesata are un TTL de {TTL_TARGET}s\n"
        f"TOTAL Cereri L7 inregistrate de On-Ramp WAF: {total_req_l7}\n\n"
        f" >> Trafic Permis (Clean): {total_clean}\n"
        f" >> Trafic Blocat (Total): {total_blocate}\n"
        f"      - HTTP Flood (429):  {total_flood}\n"
        f"      - SQL Injection:     {total_sqli}\n"
        f"      - XSS:               {total_xss}\n"
        f"--------------------------------------------------\n"
        f"Cereri redirectionate la Origin (Off-Ramp Cache Miss): {statistici['OFF_RAMP']['ORIGIN_MISS']}\n"
        f"Eficienta globala WAF + CDN: {procent_protectie:.1f}%\n"
    )

    plt.figtext(0.5, 0.04, text_rezultat, ha="center", fontsize=10, family='monospace',
                bbox=dict(boxstyle="round,pad=0.5", facecolor="#f8f9fa", edgecolor="#ced4da"))

    plt.subplots_adjust(bottom=0.35, hspace=0.45)
    plt.show()

if __name__ == "__main__":
    print("=== STARTING END-TO-END PLATFORM TEST ===")
    scenariul_1_flash_crowd()
    scenariul_2_dns_amplification()
    scenariul_3_http_flood()
    scenariul_4_l7_signatures()
    genereaza_dashboard()