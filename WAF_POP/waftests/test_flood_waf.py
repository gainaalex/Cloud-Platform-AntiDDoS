import matplotlib
import requests
import matplotlib.pyplot as plt
import time
import concurrent.futures

matplotlib.use('TkAgg')

TARGET_URL = "http://127.0.0.1:8087/static/image.jpg"
HOST_HEADER = "edu.tuiasi.ro"
DURATA_TEST = 35
TTL_RESOURCE=5
WAF_FLOOD_WINDOW = 1
WAF_FLOOD_MAX_REQS = 50
WAF_BAN_TIMEOUT = 15


date_grafic = []


def ruleaza_test_flood():
    print("=" * 60)
    print(f"[I] Incep simularea unui atac HTTP Flood pe o resursa de Cache...")
    print("=" * 60)

    session = requests.Session()
    timp_start = time.time()
    id_cerere = 0

    # Tragem direct cu flood-ul
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        while (time.time() - timp_start) < DURATA_TEST:
            id_cerere += 1

            def _exec_intern(id_c):
                t_relativ = time.time() - timp_start
                try:
                    resp = session.get(TARGET_URL, headers={"Host": HOST_HEADER, "User-Agent": "Test"}, timeout=1)
                    node = resp.headers.get('X-WAF-Node', 'N/A')

                    # Extragem header-ul custom de cache (default este MISS daca nu e prezent)
                    x_cache = resp.headers.get('X-Cache', 'MISS')

                    if resp.status_code == 429:
                        date_grafic.append((t_relativ, "WAF: Respins (Flood)", node))
                    elif x_cache == 'HIT':
                        date_grafic.append((t_relativ, "CDN: Servit din Cache", node))
                    else:
                        date_grafic.append((t_relativ, "ORIGIN: Permis", node))
                except:
                    pass

            executor.submit(_exec_intern, id_cerere)
            time.sleep(0.005)

    time.sleep(1)
    genereaza_grafic_flood()


def genereaza_grafic_flood():
    print("\n[I] Generez graficul...")

    date_sortate = sorted(date_grafic, key=lambda x: x[0])

    timpi = [d[0] for d in date_sortate]
    statusuri = [d[1] for d in date_sortate]

    # Mapam starile pe axa Y
    mapare_y = {
        "ORIGIN: Permis": 2,
        "CDN: Servit din Cache": 1,
        "WAF: Respins (Flood)": 0
    }

    pozitii_y = [mapare_y[s] for s in statusuri]

    # Culori distinctive
    culori = []
    for s in statusuri:
        if s == "ORIGIN: Permis":
            culori.append('#000000')
        elif s == "CDN: Servit din Cache":
            culori.append('#198754')
        elif s == "WAF: Respins (Flood)":
            culori.append('#dc3545')

    p_size = [50 if s == "ORIGIN: Permis" or s == "CDN: Servit din Cache" else 1 for s in statusuri]

    # Calcul statistici precise
    total_cereri = len(date_sortate)
    total_origin = statusuri.count("ORIGIN: Permis")
    total_cdn = statusuri.count("CDN: Servit din Cache")
    total_blocate = statusuri.count("WAF: Respins (Flood)")

    text_statistici = (
        f"TTL Resursa accesata:{TTL_RESOURCE}\n"
        f"WAF Config:\n{WAF_FLOOD_MAX_REQS} cereri/ {WAF_FLOOD_WINDOW} sec\n"
        f"BAN Time={WAF_BAN_TIMEOUT} sec\n"
      
        f"STATISTICI SIMULARE:\n"
        f"-------------------------\n"
        f"Total cereri: {total_cereri}\n\n"
        f" >> Trimise la ORIGIN: {total_origin}\n"
        f" >> Rezolvate de CDN: {total_cdn}\n"
        f" >> Respinse de WAF: {total_blocate}\n"
    )

    plt.figure(figsize=(12, 5))

    # Desenam punctele
    plt.scatter(timpi, pozitii_y, c=culori, s=p_size, alpha=0.6, edgecolors='none')

    # Setari Axe
    etichete_y_valori = [0, 1, 2]
    etichete_y_text = ["WAF\n(Respins)", "CDN\n(Cache Hit)", "ORIGIN\n(Cache Miss)"]
    plt.yticks(etichete_y_valori, etichete_y_text, fontsize=10, fontweight='bold')

    plt.title('Simulare atac DDoS Flood', fontsize=14, pad=15)
    plt.xlabel('Timpul scurs de la inceperea atacului (secunde)', fontsize=12)

    plt.grid(True, linestyle=':', alpha=0.6)

    # Caseta de statistici mutata in afara graficului
    box_props = dict(boxstyle='round', facecolor='#ffffff', alpha=0.95, edgecolor='#ced4da')
    plt.text(1.02, 0.95, text_statistici, transform=plt.gca().transAxes, fontsize=10,
             verticalalignment='top', horizontalalignment='left', bbox=box_props, family='monospace')

    plt.ylim(-0.5, 2.5)
    plt.xlim(-0.5, DURATA_TEST)
    plt.subplots_adjust(right=0.75)

    plt.show()


if __name__ == "__main__":
    ruleaza_test_flood()