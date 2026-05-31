import matplotlib
import requests
import matplotlib.pyplot as plt
import time
import threading
import concurrent.futures
import random
matplotlib.use('TkAgg')

#pentru a testa strict partea de failover am oprit protectia impotriva DDoS flood
#- WAF_FLOOD_WINDOW = 1
#- WAF_FLOOD_MAX_REQS = 50000
#- WAF_BAN_TIMEOUT = 30
#- restart:"no"


TARGET_URL = "http://127.0.0.1:8080/static/image.jpg"
CRASH_URL = "http://127.0.0.1:8080/crash"
HOST_HEADER = "edu.tuiasi.ro"

#ruleaza asta cu setarile de mai sus
#docker-compose up --scale waf_node=11 --build


date_grafic = []

# Mărește puțin durata sus, ca să aibă timp să execute toate crash-urile
DURATA_TEST = 90
NR_CRASHES = 10


def trimite_crash():
    time.sleep(5)  # O mica pauza initiala ca sa vedem traficul curat la inceput

    for i in range(NR_CRASHES):
        pauza = random.uniform(0.5, 5.0)
        time.sleep(pauza)
        print(f"\n[!] ---> OPRIM NODUL {i + 1} (Dupa pauza de {pauza:.2f}s) <--- [!]\n")

        try:
            requests.get(CRASH_URL, headers={"Host": HOST_HEADER}, timeout=0.5)
        except:
            pass

        print(f"[*] Astept ca POP-ul sa izoleze nodul {i + 1}...")


        time.sleep(1)

        retea_stabila = False
        while not retea_stabila:
            # Facem un mic test de sanatate pe retea
            erori_consecutive = 0
            for _ in range(NR_CRASHES+1):  # Verificam 5 pachete rapide
                try:
                    resp = requests.get(TARGET_URL, headers={"Host": HOST_HEADER}, timeout=0.5)
                    if resp.status_code >= 500:
                        erori_consecutive += 1
                except:
                    erori_consecutive += 1
                time.sleep(0.1)

            # Daca n-am avut nicio eroare in cele NR_CRASHES+1 verificari, POP-ul s-a vindecat
            if erori_consecutive == 0:
                retea_stabila = True
                print(f"[+] Traficul s-a stabilizat. Urmatorul ciclu poate incepe.")
            else:
                # Altfel, mai asteptam jumatate de secunda si incercam iar
                time.sleep(0.5)

def executa_cerere(session, id_cerere, timp_curent_relativ):
    try:
        response = session.get(TARGET_URL, timeout=0.2)

        if response.status_code >= 500:
            date_grafic.append((timp_curent_relativ, "Eroare/Timeout"))
        else:
            waf_node = response.headers.get('X-WAF-Node', 'Eroare/Timeout')
            date_grafic.append((timp_curent_relativ, waf_node))

    except requests.exceptions.RequestException:
        date_grafic.append((timp_curent_relativ, "Eroare/Timeout"))


def ruleaza_test_statistici():
    print("=" * 60)
    print(f"[I] Incep testul statistic de Health Check...")
    print(f"[I] Se vor efectua {NR_CRASHES} crash-uri la intervale random (0.5s - 5.0s).")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({
        "Host": HOST_HEADER,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })

    threading.Thread(target=trimite_crash, daemon=True).start()

    timp_start = time.time()
    id_cerere = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        while (time.time() - timp_start) < DURATA_TEST:
            id_cerere += 1
            timp_curent_relativ = time.time() - timp_start
            executor.submit(executa_cerere, session, id_cerere, timp_curent_relativ)
            time.sleep(0.02)

    time.sleep(1)
    genereaza_grafic_statistici()


def genereaza_grafic_statistici():
    print("\n[I] Generez graficul si calculez media ferestrelor de detectie...")

    toate_nodurile = list(set([d[1] for d in date_grafic if d[1] != "Eroare/Timeout"]))
    toate_nodurile.sort()

    mapare_y = {}
    etichete_y = []

    for i, nod in enumerate(toate_nodurile):
        mapare_y[nod] = i + 1
        etichete_y.append(f"N{i + 1}")

    mapare_y["Eroare/Timeout"] = 0
    etichete_y.insert(0, "Pachete\nPierdute")

    # E CRITIC sa sortam datele, deoarece thread-urile asincrone pot insera timpii usor amestecati
    date_sortate = sorted(date_grafic, key=lambda x: x[0])

    timpi = [d[0] for d in date_sortate]
    pozitii_y = [mapare_y[d[1]] for d in date_sortate]
    culori = ['#dc3545' if y == 0 else '#0d6efd' for y in pozitii_y]

    # --- 1. CALCUL FERESTRE BRUTE (cu micro-intreruperi) ---
    ferestre_brute = []
    in_eroare = False
    start_fereastra = 0.0

    for d in date_sortate:
        timp = d[0]
        nod = d[1]

        if nod == "Eroare/Timeout":
            if not in_eroare:
                in_eroare = True
                start_fereastra = timp
        else:
            if in_eroare:
                in_eroare = False
                end_fereastra = timp
                ferestre_brute.append((start_fereastra, end_fereastra))

    if in_eroare:
        ferestre_brute.append((start_fereastra, timpi[-1]))

    # --- 2. LOGICA DE UNIFICARE (MERGE) A FERESTRELOR ---
    TOLERANTA_UNIFICARE = 2.5
    ferestre_detectie = []

    if ferestre_brute:
        current_start, current_end = ferestre_brute[0]
        for start, end in ferestre_brute[1:]:
            if start - current_end <= TOLERANTA_UNIFICARE:
                # Daca ferestrele sunt apropiate, le unim prelungind finalul
                current_end = max(current_end, end)
            else:
                # Daca e o distanta mare de timp fara erori, s-a vindecat clar. Salvam incidentul.
                ferestre_detectie.append((current_start, current_end))
                current_start, current_end = start, end


        ferestre_detectie.append((current_start, current_end))


    durate_ferestre = [end - start for start, end in ferestre_detectie]
    timp_mediu_detectie = sum(durate_ferestre) / len(durate_ferestre) if durate_ferestre else 0.0


    pachete_pierdute = len([d for d in date_grafic if d[1] == "Eroare/Timeout"])

    text_statistici = (
        f"STATISTICI:\n"
        f"-------------------------\n"
        f"Cereri procesate: {len(date_grafic)}\n"
        f"Cereri pierdute: {pachete_pierdute}\n"
        f"Noduri testate: {NR_CRASHES}\n"
        f"Incidente izolate: {len(ferestre_detectie)}\n\n"
        f"Timp Mediu Detectie: {timp_mediu_detectie:.2f} sec"
    )

    # --- DESENARE GRAFIC ---
    plt.figure(figsize=(14, 7))
    plt.scatter(timpi, pozitii_y, c=culori, s=30, alpha=0.7, edgecolors='none')

    for i, (start, end) in enumerate(ferestre_detectie):
        label_zona = 'Fereastra Detectie' if i == 0 else ""
        label_start = 'Detectie Esuata (Crash)' if i == 0 else ""
        label_end = 'Eliminat din Pool' if i == 0 else ""

        plt.axvspan(start, end, color='#dc3545', alpha=0.15, label=label_zona)
        plt.axvline(x=start, color='#dc3545', linestyle='--', linewidth=1.5, label=label_start)
        plt.axvline(x=end, color='#198754', linestyle='-', linewidth=2, label=label_end)

    plt.yticks(list(range(len(etichete_y))), etichete_y)
    plt.title('Evaluarea Detectiei Nodurilor Unhealthy in Load Balancer', fontsize=14, pad=15)
    plt.xlabel('Timpul (secunde)', fontsize=12)
    plt.ylabel('Stare Endpoint', fontsize=12)
    plt.grid(True, linestyle=':', alpha=0.6)

    box_props = dict(boxstyle='round', facecolor='#f8f9fa', alpha=0.9, edgecolor='#ced4da')

    # Mutam caseta in dreapta-sus
    plt.text(0.98, 0.95, text_statistici, transform=plt.gca().transAxes, fontsize=10,
             verticalalignment='top', horizontalalignment='right', bbox=box_props, family='monospace')

    # Mutam legenda in stanga-sus pentru a nu se suprapune cu statisticile
    plt.legend(loc='upper left')

    plt.ylim(-0.5, len(etichete_y))
    plt.xlim(0, max(timpi) if timpi else 40)
    plt.tight_layout()
    plt.show()
if __name__ == "__main__":
    ruleaza_test_statistici()