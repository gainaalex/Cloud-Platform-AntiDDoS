import time
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from attack_engine import run_flood

TARGET = "http://localhost:8080/"
SCENARII_CERERI = [10, 50, 100, 250, 500, 750, 1000]
PAUZA_RESET_REDIS = 1.2


def start_crescendo_test():
    results_200 = []
    results_429 = []

    print(f"--- Incepe simularea celor {len(SCENARII_CERERI)} cazui de test pe {TARGET} ---")

    for count in SCENARII_CERERI:
        print(f"[*I] Testez cu {count} cereri...")

        start_time = time.time()
        round_stats = run_flood(TARGET, count)
        duration = time.time() - start_time

        results_200.append(round_stats["200"])
        results_429.append(round_stats["429"])

        print(f"--- Finalizat in {duration:.2f}s | OK: {round_stats['200']} | Blocat: {round_stats['429']}")

        time.sleep(PAUZA_RESET_REDIS)

    plt.plot(SCENARII_CERERI, results_200, label='Succes (200 OK)', marker='o', color='green')
    plt.plot(SCENARII_CERERI, results_429, label='Blocat (429 Too Many Requests)', marker='x', color='red')

    plt.title('Analiza WAF Rate Limiting')
    plt.xlabel('Volum Cereri Trimise (total)')
    plt.ylabel('Numar Raspunsuri Receptionate')
    plt.legend()
    plt.grid(True, linestyle=':', alpha=0.7)


    plt.savefig('ddos_on_waf_stats.jpg')
    print("\n[!] Simularea s-a incheiat. Graficul a fost salvat.")
    plt.show()

if __name__ == "__main__":
    start_crescendo_test()