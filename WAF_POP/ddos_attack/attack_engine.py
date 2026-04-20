import urllib.request
import threading
import time


def run_flood(target_url, total_requests, thread_limit=10):
    stats = {"200": 0, "429": 0, "other": 0}
    stats_lock = threading.Lock()
    threads = []

    def send_request():
        try:
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    with stats_lock: stats["200"] += 1
        except Exception as e:
            code = getattr(e, 'code', None)
            with stats_lock:
                if code == 429:
                    stats["429"] += 1
                else:
                    stats["other"] += 1

    for i in range(total_requests):
        t = threading.Thread(target=send_request)
        threads.append(t)
        t.start()

        # Limitare pentru a nu bloca stack-ul de retea local
        if i % thread_limit == 0:
            time.sleep(0.01)

    for t in threads:
        t.join()

    return stats