import hmac
import hashlib
import time
import urllib.parse

API_KEY = "micunealta-secreta"
DOMAIN = "licenta.ro"
ORIGIN_IP = "89.89.89.89"
PORT = 5050

timestamp = str(int(time.time()))

message = f"{DOMAIN}:{ORIGIN_IP}:{timestamp}"
signature = hmac.new(API_KEY.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()

encoded_ip = urllib.parse.quote(ORIGIN_IP)

print("\n comanda pt register in platforma")
reg_url = f"http://127.0.0.1:{PORT}/register?domain={DOMAIN}&origin={encoded_ip}&t={timestamp}&sig={signature}"
print(f'curl -X POST "{reg_url}"\n')

print("\n comanda pt unregister in platforma")
unreg_url = f"http://127.0.0.1:{PORT}/unregister?domain={DOMAIN}&original_ip={encoded_ip}&t={timestamp}&sig={signature}"
print(f'curl -X POST "{unreg_url}"\n')