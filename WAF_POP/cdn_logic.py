import redis
import json
import time
from email.utils import parsedate_to_datetime


class CDNManager:
    def __init__(self, redis_host='localhost', redis_port=6379):
        self.r = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

    # REQ: Parser full Cache-Control (RFC 9111 & 5861)
    def parse_cache_control(self, cc_header):
        directives = {
            'max-age': None, 's-maxage': None,
            'stale-while-revalidate': 0, 'stale-if-error': 0,
            'no-store': False, 'private': False, 'global-no-cache': False,
            'must-revalidate': False, 'public': False,
            'no-cache-fields': []
        }
        if not cc_header:
            return directives

        parts = [p.strip().lower() for p in cc_header.split(',')]
        for p in parts:
            if '=' in p:
                key, val = p.split('=', 1)
                val = val.strip('"\'')
                if key in ['max-age', 's-maxage', 'stale-while-revalidate', 'stale-if-error']:
                    directives[key] = int(val) if val.isdigit() else 0
                elif key == 'no-cache':
                    directives['no-cache-fields'] = [f.strip() for f in val.split(',')]
            else:
                if p == 'no-cache':
                    directives['global-no-cache'] = True
                elif p in directives:
                    directives[p] = True

        # REQ/RFC: must-revalidate anuleaza posibilitatea de a servi date stale
        if directives['must-revalidate']:
            directives['stale-while-revalidate'] = 0
            directives['stale-if-error'] = 0

        return directives

    # REQ: Cheie base: host+port+path+query. Field separat pt Vary. Fara metoda.
    def get_redis_keys(self, host, port, path, req_headers, resp_headers=None):
        base_key = f"cdn:{host}:{port}:{path}"

        vary_signature = "default"
        if resp_headers:
            vary_header = resp_headers.get('Vary', '')
            if vary_header and vary_header != '*':
                vary_parts = []
                for v in vary_header.split(','):
                    v = v.strip()
                    val = req_headers.get(v, '')
                    vary_parts.append(f"{v.lower()}={val}")
                vary_signature = "&".join(vary_parts)

        return base_key, vary_signature

    # REQ: Evaluare stocare (Auth, 206, no-store, private)
    def is_cacheable(self, method, req_headers, resp_status, resp_headers):
        if method not in ['GET', 'HEAD']:
            return False

        if resp_status == 206:
            print("[*I] [CDN] Bypass: HTTP 206 nu este stocat.")
            return False

        if req_headers.get('Authorization') or resp_headers.get('Authorization'):
            print("[*W] [CDN] Bypass: Date sensitive detectate.")
            return False

        cc = self.parse_cache_control(resp_headers.get('Cache-Control', ''))
        if cc['no-store'] or cc['private']:
            print("[*I] [CDN] Bypass: Regula no-store/private incalcata.")
            return False

        if self.calculate_freshness(cc, resp_headers) <= 0:
            print("[*W] [CDN] Bypass: Lipsa timp expirare valid.")
            return False

        return True

    # REQ: Freshness (s-maxage > max-age > Expires)
    def calculate_freshness(self, cc_directives, resp_headers):
        if cc_directives['s-maxage'] is not None:
            return cc_directives['s-maxage']
        if cc_directives['max-age'] is not None:
            return cc_directives['max-age']

        expires_str = resp_headers.get('Expires')
        if expires_str:
            try:
                dt = parsedate_to_datetime(expires_str)
                ttl = int(dt.timestamp() - time.time())
                return ttl if ttl > 0 else 0
            except Exception as e:
                print(f"[*E] [CDN] Eroare parsare Expires: {e}")
        return 0

    # REQ: Salvare
    def store_response(self, host, port, path, req_headers, status, resp_headers, body):
        base_key, vary_sig = self.get_redis_keys(host, port, path, req_headers, resp_headers)
        cc = self.parse_cache_control(resp_headers.get('Cache-Control', ''))
        freshness_ttl = self.calculate_freshness(cc, resp_headers)

        safe_headers = {}
        # REQ: Ignoram Connection si campurile specificate in no-cache
        for k, v in resp_headers.items():
            k_low = k.lower()
            if k_low == 'connection' or k_low in cc['no-cache-fields']:
                continue
            safe_headers[k] = v

        data_to_store = {
            "status": status,
            "headers": safe_headers,
            "body": body,
            "stored_at": time.time(),
            "freshness_ttl": freshness_ttl,
            "stale_while_revalidate": cc['stale-while-revalidate'],
            "stale_if_error": cc['stale-if-error'],
            "global_no_cache": cc['global-no-cache']
        }

        # Timeout fizic Redis = cat e fresh + maximul de timp de gratie (stale)
        max_stale = max(cc['stale-while-revalidate'], cc['stale-if-error'])
        redis_hard_ttl = freshness_ttl + max_stale

        self.r.hset(base_key, vary_sig, json.dumps(data_to_store))
        self.r.expire(base_key, redis_hard_ttl)
        print(f"[*I] [CDN] Salvat {base_key} [Vary: {vary_sig} | TTL: {freshness_ttl}s]")

    # REQ: Invalidate la actiuni POST/PUT/DELETE
    def invalidate_mutations(self, method, host, port, path, status):
        if method in ['POST', 'PUT', 'DELETE', 'PATCH'] and 100 <= status < 400:
            base_key = f"cdn:{host}:{port}:{path}"
            if self.r.delete(base_key):
                print(f"[*I] [CDN-INV] Invalidate reusit pt {base_key} dupa {method}.")

    # REQ: Freshening (Revalidare la Origin: 304)
    def freshen_cache(self, host, port, path, req_headers, cached_data, new_headers):
        base_key, vary_sig = self.get_redis_keys(host, port, path, req_headers)
        old_headers = cached_data.get('headers', {})

        # REQ: Update headere si Cache Poisoning Check
        for k, v in new_headers.items():
            if k.lower().startswith('content-'):
                print(f"[*W] [CDN-SEC] Ignorat header malitios/nesigur {k} la 304.")
                continue
            old_headers[k] = v

        cc = self.parse_cache_control(new_headers.get('Cache-Control', ''))
        freshness_ttl = self.calculate_freshness(cc, new_headers)

        cached_data['headers'] = old_headers
        cached_data['stored_at'] = time.time()

        if freshness_ttl > 0:
            cached_data['freshness_ttl'] = freshness_ttl
            cached_data['stale_while_revalidate'] = cc['stale-while-revalidate']
            cached_data['stale_if_error'] = cc['stale-if-error']
            cached_data['global_no_cache'] = cc['global-no-cache']

        redis_hard_ttl = cached_data['freshness_ttl'] + max(cached_data['stale_while_revalidate'],
                                                            cached_data['stale_if_error'])

        self.r.hset(base_key, vary_sig, json.dumps(cached_data))
        self.r.expire(base_key, redis_hard_ttl)
        print(f"[*I] [CDN-FRESH] Cache revalidat pt {base_key} [Vary: {vary_sig}]")

    # REQ: Validare de la client. Daca clientul are resursa (ETag/LMod), dam 304 direct.
    def validate_client_request(self, client_headers, cached_data):
        # Daca resursa noastra e invechita sau Origin a zis no-cache,
        # nu putem garanta ca ce are clientul e corect, delegam revalidarea.
        age = time.time() - cached_data.get('stored_at', 0)
        if age >= cached_data.get('freshness_ttl', 0) or cached_data.get('global_no_cache'):
            return False

        cached_headers = cached_data.get('headers', {})

        c_etag = client_headers.get('If-None-Match')
        s_etag = cached_headers.get('ETag')
        # ETag are prioritate (RFC 9111)
        if c_etag and s_etag:
            if c_etag == s_etag:
                print("[*I] [CDN-CLIENT] Match If-None-Match. Returnam 304.")
                return True
            return False  # Daca ETag e prezent dar nu face match, respingem

        c_lmod = client_headers.get('If-Modified-Since')
        s_lmod = cached_headers.get('Last-Modified')
        if c_lmod and s_lmod and c_lmod == s_lmod:
            print("[*I] [CDN-CLIENT] Match If-Modified-Since. Returnam 304.")
            return True

        return False