import socket
import time
import threading

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use('TkAgg')
from dnslib import DNSRecord

RESOLVER_IP = "127.0.0.1"
RESOLVER_PORT = 5333
DOMENIU_TEST = "api.mycloud.ro"

DURATA_ATAC_SECUNDE = 10
RATA_CERERI_PE_SECUNDA = 250
BAN_TIME=1
DNS_FLOOD_WINDOW = 1
DNS_FLOOD_MAX_REQS = 80


date_grafic = []
lock_date = threading.Lock()
timp_start_global = 0
id_global_cerere = 0


def trimite_cerere_dns(id_cerere):
    try:
        q = DNSRecord.question(DOMENIU_TEST)
        pachet = q.pack()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)

        # 1. Inregistram timpul EXACT cand pachetul pleaca spre server
        timp_start_req = time.time()
        timp_trimitere_relativ = timp_start_req - timp_start_global

        sock.sendto(pachet, (RESOLVER_IP, RESOLVER_PORT))

        data, _ = sock.recvfrom(512)
        raspuns = DNSRecord.parse(data)
        rcode_name = getattr(raspuns.header, 'rcode', 'UNKNOWN')

        with lock_date:
            date_grafic.append((timp_trimitere_relativ, id_cerere, 'Succes'))

    except socket.timeout:
        with lock_date:
            date_grafic.append((timp_trimitere_relativ, id_cerere, 'Blocat'))
    except Exception as e:
        pass
    finally:
        sock.close()


def genereaza_grafic():
    print("[I:] Generez graficul atacului...")
    if not date_grafic:
        return

    # Sortam datele cronologic
    date_grafic.sort(key=lambda x: x[0])
    timpi = [d[0] for d in date_grafic]

    cumulativ_succes = []
    cumulativ_blocat = []
    c_s = 0
    c_b = 0

    momente_ban = []

    stare_curenta = 'Succes'

    for pachet in date_grafic:
        timp_curent = pachet[0]
        status = pachet[2]

        if status == 'Succes':
            c_s += 1

            if stare_curenta == 'Blocat':
                stare_curenta = 'Succes'
        else:
            c_b += 1
            if stare_curenta == 'Succes':
                momente_ban.append(timp_curent)
                stare_curenta = 'Blocat'

        cumulativ_succes.append(c_s)
        cumulativ_blocat.append(c_b)

    plt.figure(figsize=(11, 8)) # Am marit putin inaltimea pentru a incapea caseta

    label_verde = f'Trafic Permis ({c_s} cereri)'
    label_rosu = f'Trafic Blocat ({c_b} cereri)'

    plt.step(timpi, cumulativ_succes, color='#28a745', label=label_verde, linewidth=2.5, where='post')
    plt.step(timpi, cumulativ_blocat, color='#dc3545', label=label_rosu, linewidth=2.5, where='post')

    plt.fill_between(timpi, cumulativ_succes, color='#28a745', alpha=0.15, step='post')
    plt.fill_between(timpi, cumulativ_blocat, color='#dc3545', alpha=0.15, step='post')

    for i, t in enumerate(momente_ban):
        lbl = 'Ban Activat (Detectie DDoS)' if i == 0 else ""
        plt.axvline(x=t, color='#dc3545', linestyle='--', linewidth=1.5, alpha=0.8, label=lbl)

    plt.title(f"Testare DNS Flood", fontsize=14, pad=15, fontweight='bold')
    plt.xlabel('Timp (secunde)', fontsize=12)
    plt.ylabel('Volumul cererilor', fontsize=12)
    plt.legend(loc='upper left', fontsize=10)
    plt.grid(True, linestyle=':', alpha=0.7)

    plt.xlim(left=0)

    max_y = max(max(cumulativ_succes) if cumulativ_succes else 0,
                max(cumulativ_blocat) if cumulativ_blocat else 0)
    plt.ylim(bottom=0, top=max_y + (max_y * 0.2))

    # --- GENERARE CASETA TEXT ---
    total_cereri = c_s + c_b
    rata_efectiva = total_cereri / DURATA_ATAC_SECUNDE if DURATA_ATAC_SECUNDE > 0 else 0

    text_statistici = (
        f"PARAMETRI DE TEST CONFIGURATI:\n"
        f"-------------------------------------------------\n"
        f"Tinta atac:            {DOMENIU_TEST}\n"
        f"Durata simulare:       {DURATA_ATAC_SECUNDE} secunde\n"
        f"Flux cereri acceptabil: {DNS_FLOOD_MAX_REQS} cereri/{DNS_FLOOD_WINDOW}s\n"
        f"Timp Ban:       {BAN_TIME} secunde\n"
        f"\nREZULTATE OBTINUTE IN URMA ATACULUI:\n"
        f"-------------------------------------------------\n"
        f"TOTAL Pachete emise:   {total_cereri}\n"
        f"Rata efectiva atinsa:  {rata_efectiva:.1f} cereri/secunda\n"
        f" >> Trafic Permis:     {c_s} cereri\n"
        f" >> Trafic Blocat:     {c_b} cereri\n"
    )

    box_props = dict(boxstyle='round,pad=0.6', facecolor='#f8f9fa', alpha=0.95, edgecolor='#ced4da')
    plt.figtext(0.5, 0.03, text_statistici, ha="center", fontsize=10, family='monospace', bbox=box_props)

    # Ridicam graficul pentru a face loc complet textului
    plt.subplots_adjust(bottom=0.35)
    plt.show()


def porneste_atac_simulat():
    global timp_start_global, id_global_cerere
    print("=" * 60)
    print(f"[I:] Pornesc flood sustinut timp de {DURATA_ATAC_SECUNDE} secunde...")

    timp_start_global = time.time()
    threads_active = []

    while (time.time() - timp_start_global) < DURATA_ATAC_SECUNDE:
        for _ in range(int(RATA_CERERI_PE_SECUNDA / 10)):
            id_global_cerere += 1
            t = threading.Thread(target=trimite_cerere_dns, args=(id_global_cerere,))
            threads_active.append(t)
            t.start()

        time.sleep(0.1)

    print("[I:] Atacul s-a oprit. Astept inchiderea conexiunilor ramase...")
    for t in threads_active:
        t.join()

    print("=" * 60)
    genereaza_grafic()


if __name__ == "__main__":
    porneste_atac_simulat()