import matplotlib
import requests
import matplotlib.pyplot as plt
import time
import threading
import concurrent.futures

matplotlib.use('TkAgg')


#pentru a testa strict partea de failover am oprit protectia impotriva DDoS flood
#- WAF_FLOOD_WINDOW = 1
#- WAF_FLOOD_MAX_REQS = 50000
#- WAF_BAN_TIMEOUT = 30

TARGET_URL = "http://127.0.0.1:8080/static/image.jpg"
CRASH_URL = "http://127.0.0.1:8080/crash"
HOST_HEADER = "edu.tuiasi.ro"
#ruleaza asta cu setarile de mai sus
#docker-compose up --scale waf_node=3 --build
DURATA_TEST = 15
MOMENT_CRASH = 5
NR_CRASHES = 30

date_grafic = []


def trimite_crash():
    time.sleep(MOMENT_CRASH)
    print("\n[!] ---> TRIMIT COMANDA DE CRASH <--- [!]\n")
    try:
        for i in range(NR_CRASHES):
            requests.get(CRASH_URL, headers={"Host": HOST_HEADER}, timeout=2)
            time.sleep(0.001)
    except:
        pass


def executa_cerere(session, id_cerere, timp_curent_relativ):
    try:
        response = session.get(TARGET_URL, timeout=0.2)

        if response.status_code >= 500:
            date_grafic.append((timp_curent_relativ, "Eroare/Timeout"))
            print(f"[{timp_curent_relativ:.1f}s] Cerere {id_cerere:03d} -> EROARE POP ({response.status_code})")
        else:
            waf_node = response.headers.get('X-WAF-Node', 'Eroare/Timeout')
            date_grafic.append((timp_curent_relativ, waf_node))
            print(f"[{timp_curent_relativ:.1f}s] Cerere {id_cerere:03d} -> {waf_node}")

    except requests.exceptions.RequestException:
        date_grafic.append((timp_curent_relativ, "Eroare/Timeout"))
        print(f"[{timp_curent_relativ:.1f}s] Cerere {id_cerere:03d} -> EROARE CONEXIUNE")


def ruleaza_test_failover():
    print("=" * 60)
    print(f"[I] Incep testul de High Availability pe POP...")
    print(f"[I] Nodurile vor pica intentionat la secunda {MOMENT_CRASH}.")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({
        "Host": HOST_HEADER,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })

    threading.Thread(target=trimite_crash, daemon=True).start()

    timp_start = time.time()
    id_cerere = 0

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=50) as executor:  # Am marit max_workers pentru a suporta traficul mai dens
        while (time.time() - timp_start) < DURATA_TEST:
            id_cerere += 1
            timp_curent_relativ = time.time() - timp_start

            executor.submit(executa_cerere, session, id_cerere, timp_curent_relativ)

            time.sleep(0.01)  # Pauza redusa pentru a "tranzactiona" mult mai multe cereri

    time.sleep(0.5)  # Timp de gratie usor marit pt finalizarea thread-urilor
    genereaza_grafic_failover()


def genereaza_grafic_failover():
    print("\n[I] Generez graficul de failover...")

    toate_nodurile = list(set([d[1] for d in date_grafic if d[1] != "Eroare/Timeout"]))
    toate_nodurile.sort()

    mapare_y = {}
    etichete_y = []

    for i, nod in enumerate(toate_nodurile):
        mapare_y[nod] = i + 1
        etichete_y.append(f"N{i + 1}")
        print(f"[Mapare Licenta] {nod} ---> N{i + 1}")

    mapare_y["Eroare/Timeout"] = 0
    etichete_y.insert(0, "Pachete\nPierdute")

    timpi = [d[0] for d in date_grafic]
    pozitii_y = [mapare_y[d[1]] for d in date_grafic]
    culori = ['#dc3545' if y == 0 else '#0d6efd' for y in pozitii_y]

    total_cereri = len(date_grafic)
    cereri_pierdute = len([d for d in date_grafic if d[1] == "Eroare/Timeout"])

    cereri_pe_nod = {f"N{i + 1}": 0 for i in range(len(toate_nodurile))}
    for d in date_grafic:
        if d[1] != "Eroare/Timeout":
            nume_mapat = f"N{mapare_y[d[1]]}"
            cereri_pe_nod[nume_mapat] += 1

    timp_revenire = 0.0
    timp_prima_eroare = None
    timp_prima_recuperare = None

    for d in date_grafic:
        timp = d[0]
        nod = d[1]

        if timp >= MOMENT_CRASH and nod == "Eroare/Timeout":
            if timp_prima_eroare is None:
                timp_prima_eroare = timp
        elif timp_prima_eroare is not None and nod != "Eroare/Timeout":
            timp_revenire = timp - timp_prima_eroare
            timp_prima_recuperare = timp
            break

    text_statistici = (
        f"STATISTICI TRAFIC ON RAMP:\n"
        f"------------------------\n"
        f"Total pachete: {total_cereri}\n"
        f"Pachete pierdute (Dropped): {cereri_pierdute}\n"
        f"Timp recuperare (RT): {timp_revenire:.2f} sec\n\n"
        f"DISTRIBUTIE PER NODURI:\n"
    )
    for nod_nume, count in cereri_pe_nod.items():
        text_statistici += f" > {nod_nume}: {count} pachete\n"

    plt.figure(figsize=(12, 6))
    plt.scatter(timpi, pozitii_y, c=culori, s=40, alpha=0.6, edgecolors='none')

    plt.axvline(x=MOMENT_CRASH, color='#dc3545', linestyle='--', linewidth=2, label='Moment CRASH')

    if timp_prima_recuperare:
        plt.axvline(x=timp_prima_recuperare, color='#198754', linestyle='-', linewidth=2, label='Moment Revenire')

    plt.yticks(list(range(len(etichete_y))), etichete_y)
    plt.title('High Availability & Failover la nivel de POP', fontsize=14, pad=15)
    plt.xlabel('Timp (secunde)', fontsize=12)
    plt.ylabel('Endpoint-ul WAF utilizat', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)

    box_props = dict(boxstyle='round', facecolor='#f8f9fa', alpha=0.9, edgecolor='#ced4da')
    plt.text(0.02, 0.05, text_statistici, transform=plt.gca().transAxes, fontsize=10,
             verticalalignment='bottom', bbox=box_props, family='monospace')

    plt.legend(loc='upper right')
    plt.ylim(-0.5, len(etichete_y))
    plt.xlim(0, DURATA_TEST)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    ruleaza_test_failover()