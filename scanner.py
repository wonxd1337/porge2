# scanner.py - FIXED VERSION
# Fixes applied:
#   [FIX-5]  make_request_with_retry: proxied call pakai _proxied_request
#            (per-request session), bukan shared self.session → race condition
#   [FIX-6]  HangWatchdog tick di setiap milestone penting
#   [FIX-7]  process_ip: wait_if_refreshing() sebelum mulai domain scan batch
#            sehingga proxy refresh tidak memotong domain scan
#   [FIX-9]  process_ip: domain yang gagal (exception/timeout) di-retry
#            sekali lagi setelah batch selesai — domain tidak hilang
#   [FIX-10] _reverse_loop: per-attempt watchdog tick + log budget sisa

import requests
import re
import time
import socket
import threading
import random
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from config import Config
from cache_manager import get_watchdog

try:
    import socks
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False
    print("[!] SOCKS5 support not available. Install: pip install PySocks")

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

_DNS_TIMEOUT = 4   # detik per resolve attempt

# ─────────────────────────────────────────────────────────
#  DNS resolve dengan timeout
# ─────────────────────────────────────────────────────────
def _dns_resolve_with_timeout(hostname, port=80, timeout=_DNS_TIMEOUT):
    result = []
    def _do():
        try:
            addrs = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
            result.extend(addrs)
        except Exception:
            pass
    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else None


# ─────────────────────────────────────────────────────────
#  SCANNER
# ─────────────────────────────────────────────────────────
class MovableTypeScanner:
    # Per-IP timeout: reverse budget + domain scan buffer (untuk watchdog reference)
    IP_PROCESS_TIMEOUT = getattr(Config, 'IP_PROCESS_TIMEOUT',
                                 Config.REVERSE_RETRY_TOTAL_BUDGET + 120)

    def __init__(self, proxy_manager, cache_manager, main_reference=None):
        self.ua            = UserAgent()
        self.proxy_manager = proxy_manager
        self.cache_manager = cache_manager
        self.main          = main_reference
        self.found_urls    = OrderedDict()
        self.found_urls_max = Config.FOUND_URLS_MAX
        self.lock          = threading.Lock()
        self._watchdog     = get_watchdog()

        self.headers = {
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT":             "1",
            "Connection":      "close"
        }

        # Session non-proxy (domain scan langsung)
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1, max_retries=0, pool_block=False)
        self.session.mount('http://',  adapter)
        self.session.mount('https://', adapter)
        self.output_files = Config.OUTPUT_FILES

    # ── per-request session untuk proxied call ─────────────
    def _proxied_request(self, method, url, proxy_dict, timeout, headers=None, **extra):
        """Per-request session → bebas pool exhaustion & race condition.
        [FIX-5] make_request_with_retry juga pakai ini."""
        import requests as _rq
        s = _rq.Session()
        try:
            a = _rq.adapters.HTTPAdapter(
                pool_connections=1, pool_maxsize=1, max_retries=0)
            s.mount('http://',  a)
            s.mount('https://', a)
            hdrs = dict(headers if headers is not None else self.headers)
            hdrs.setdefault("User-Agent", self.ua.random)
            kwargs = dict(timeout=timeout, verify=False, headers=hdrs, **extra)
            if proxy_dict:
                kwargs['proxies'] = proxy_dict
            return s.get(url, **kwargs) if method.lower() == 'get' else s.post(url, **kwargs)
        finally:
            s.close()

    # ── make_request_with_retry (legacy, dipakai wp2shell dll) ──
    def make_request_with_retry(self, url, method='get', **kwargs):
        """[FIX-5] Proxied call pakai _proxied_request (per-session),
        bukan self.session (shared pool_maxsize=1 → race condition)."""
        last_proxy = None
        for attempt in range(Config.MAX_RETRIES):
            try:
                proxy_dict = self.proxy_manager.get_proxy_for_retry(attempt, last_proxy)
                if proxy_dict:
                    last_proxy = list(proxy_dict.values())[0]

                proxy_used = last_proxy
                start_time = time.time()

                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random
                if 'headers' in kwargs:
                    headers.update(kwargs.pop('headers'))

                timeout = kwargs.pop('timeout', Config.TIMEOUT_REVERSE)
                kwargs.pop('proxies', None)
                kwargs.pop('verify',  None)

                if proxy_dict:
                    # [FIX-5] per-request session untuk proxied call
                    response = self._proxied_request(
                        method, url, proxy_dict, timeout, headers, **kwargs)
                else:
                    kwargs.update(headers=headers, timeout=timeout, verify=False)
                    response = (self.session.get(url, **kwargs)
                                if method.lower() == 'get'
                                else self.session.post(url, **kwargs))

                rt = time.time() - start_time
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, True, rt)
                return response

            except Exception:
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, False)
                if attempt < Config.MAX_RETRIES - 1:
                    time.sleep(Config.RETRY_DELAY * (attempt + 1) + random.uniform(0, 1))
        return None

    # ── URL builder ────────────────────────────────────────
    def _reverse_url(self, ip, source="hackertarget"):
        # source 'tntcode' sudah dicabut (Cloudflare); semua pakai hackertarget
        return f"https://api.hackertarget.com/reverseiplookup/?q={ip}"

    # ── reverse loop dengan hang watchdog ─────────────────
    def _reverse_loop(self, fetch_domains, cache_key, source, ip,
                      use_cache=True, state_ref=None):
        """[FIX-10] Tick watchdog per attempt; log budget tersisa.

        [NO-REV-CACHE] use_cache=False untuk reverse IP (key ht_):
        hasil TIDAK di-cache (baca/tulis) — selalu fresh.

        state_ref (dict, optional):
            Shared mutable state antara _reverse_loop dan fetch_domains callback.
            _reverse_loop menulis 'proxy_used' sebelum tiap call ke fetch_domains,
            fetch_domains menulis 'quota_burned'=True jika HT balas error quota.
            Ini satu-satunya cara aman untuk share state antara dua fungsi berbeda
            scope tanpa mengubah signature fetch_domains(response).

            BUG YANG DIPERBAIKI:
            [BUG-1] fetch() di reverse_ip_hackertarget mereferensi proxy_used
                    yang ada di local scope _reverse_loop — NameError saat runtime.
            [BUG-2] last_quota_burn di _reverse_loop tidak pernah di-set True
                    karena _quota_flag (di scope berbeda) tidak terhubung.
                    Fast-delay logic setelah quota burn tidak pernah berjalan.
        """
        if use_cache:
            cached = self.cache_manager.get_reverse_cache(cache_key)
            if cached:
                return cached

        deadline   = time.time() + Config.REVERSE_RETRY_TOTAL_BUDGET
        attempt    = 0
        last_proxy = None
        base_delay = Config.REVERSE_RETRY_BASE_DELAY
        max_delay  = Config.REVERSE_RETRY_MAX_DELAY

        last_quota_burn = False
        while attempt < Config.REVERSE_MAX_ATTEMPTS and time.time() < deadline:
            budget_left = deadline - time.time()
            self._watchdog.tick(f"reverse:{ip} attempt={attempt} budget={budget_left:.0f}s")

            proxy_dict = self.proxy_manager.get_proxy_for_retry(attempt, last_proxy)
            if proxy_dict:
                last_proxy = list(proxy_dict.values())[0]
            proxy_used = last_proxy
            start_time = time.time()

            # [BUG-1 FIX] Tulis proxy_used ke state_ref SEBELUM memanggil
            # fetch_domains sehingga callback bisa membacanya tanpa NameError.
            if state_ref is not None:
                state_ref['proxy_used']    = proxy_used
                state_ref['quota_burned']  = False   # reset tiap attempt

            headers = self.headers.copy()
            headers["User-Agent"] = self.ua.random

# Di method _reverse_loop, GANTI blok try ini:

            domains = None
            try:
                response = self._proxied_request(
                    'get', self._reverse_url(ip, source),
                    proxy_dict, Config.REVERSE_PROXY_TIMEOUT, headers)

                # [QUOTA] Increment daily counter — HT menerima request ini
                # (response ada, baik sukses maupun error quota).
                # Proxy yang gagal connect (exception) TIDAK di-increment.
                if response is not None and proxy_used:
                    self.proxy_manager.quota_increment(proxy_used)

                domains = fetch_domains(response)
            except Exception:
                # Proxy gagal connect — HT tidak menerima request,
                # jadi TIDAK increment quota counter
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, False)

            # [BUG-2 FIX] Baca quota_burned yang di-set oleh fetch_domains callback.
            # Sebelumnya last_quota_burn tidak pernah True karena tidak ada
            # koneksi antara _quota_flag di scope lain dengan last_quota_burn di sini.
            if state_ref is not None:
                last_quota_burn = state_ref.get('quota_burned', False)

            if domains:
                rt = time.time() - start_time
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, True, rt)
                if use_cache:
                    self.cache_manager.save_reverse_cache(cache_key, domains, source)
                print(f"[+] {source} {ip}: {len(domains)} domains (attempt {attempt+1})",
                      flush=True)
                return domains

            # [QUOTA-BURNED-FAST] Kalau quota burn terdeteksi (sekarang bisa
            # karena state_ref menghubungkan fetch dan _reverse_loop):
            # delay pendek 2-4s saja — proxy berikutnya sudah pasti berbeda
            # (get_proxy_for_retry menolak proxy yg burned).
            # Kalau bukan quota, delay backoff eksponensial seperti biasa.
            if last_quota_burn:
                delay = random.uniform(2, 4)
                last_quota_burn = False
            else:
                delay = min(base_delay * (2 ** attempt), max_delay) + random.uniform(0, 1)
            delay = min(delay, max(0, deadline - time.time()))
            attempt += 1
            if attempt < Config.REVERSE_MAX_ATTEMPTS and delay > 0:
                time.sleep(delay)

        print(f"[-] {source} {ip}: tidak dapat domain setelah {attempt} attempt "
              f"(budget habis / max_attempts tercapai)", flush=True)
        return []

    def reverse_ip_hackertarget(self, ip):
        cache_key    = f"ht_{ip}"
        _ERR_MARKERS = ('error', 'api count exceeded', 'quota',
                        'no dns a records', 'increase quota', 'rate limit')

        # [BUG-1 & BUG-2 FIX] _state dict sebagai shared mutable state antara
        # fetch() dan _reverse_loop().
        # - _reverse_loop menulis 'proxy_used' sebelum tiap call ke fetch()
        # - fetch() membaca 'proxy_used' dari _state (bukan dari scope _reverse_loop
        #   yang tidak bisa diakses → NameError sebelumnya)
        # - fetch() menulis 'quota_burned'=True jika HT balas error quota
        # - _reverse_loop membaca 'quota_burned' untuk logika fast-delay
        #   (sebelumnya last_quota_burn tidak pernah True karena tidak ada
        #   koneksi antara _quota_flag dan last_quota_burn di scope berbeda)
        _state = {'proxy_used': None, 'quota_burned': False}

        def fetch(response):
            if response is None or not response.text:
                return []
            text = response.text.strip()
            tl   = text.lower()

            if any(m in tl for m in _ERR_MARKERS):
                _marker_msg  = text[:60]
                # [BUG-1 FIX] Baca proxy_used dari _state, bukan dari scope
                # _reverse_loop yang tidak accessible → tidak ada lagi NameError.
                proxy = _state.get('proxy_used')
                is_quota = any(k in tl for k in
                               ('api count exceeded', 'increase quota', 'quota', 'rate limit'))
                if proxy and is_quota:
                    self.proxy_manager.mark_quota_burned(proxy)
                    # [BUG-2 FIX] Set 'quota_burned' di _state.
                    # _reverse_loop membaca ini setelah fetch() return untuk
                    # menentukan delay (2-4s cepat vs backoff eksponensial).
                    _state['quota_burned'] = True
                    print(f"[-] hackertarget {ip}: {_marker_msg!r} "
                          f"— proxy {proxy} quota-burned 30m, "
                          f"ganti proxy berikutnya", flush=True)
                else:
                    # Error lain (no dns a records, dsb) — TIDAK mark quota burn
                    print(f"[-] hackertarget {ip}: {_marker_msg!r}", flush=True)
                return []

            # Validasi: tiap baris harus terlihat seperti domain, bukan IP/noise
            domains = []
            for line in text.split('\n'):
                d = line.strip().lower()
                if not d:
                    continue
                if (' ' in d) or ('.' not in d):
                    continue
                if not all(c.isalnum() or c in '.-' for c in d):
                    continue
                parts = d.split('.')
                if len(parts) < 2 or not all(parts):
                    continue
                if len(parts[-1]) < 2:
                    continue
                # [BUG-5 FIX] Filter IPv4 address — HT kadang kirim IP di
                # response (mis: "1.2.3.10") yang lolos filter domain karena
                # digit valid sebagai alnum. IP bukan domain, buang.
                if all(p.isdigit() for p in parts):
                    continue
                domains.append(d)
            return domains

        return self._reverse_loop(fetch, cache_key, 'hackertarget', ip,
                                  use_cache=False, state_ref=_state)

    # ── domain scan helpers ────────────────────────────────
    def get_base_url_with_www(self, domain, session=None):
        sess      = session or self.session
        cache_key = f"base_{domain}"
        cached    = self.cache_manager.get_reverse_cache(cache_key)
        if cached:
            return cached
        try:
            resolved = _dns_resolve_with_timeout(f"www.{domain}")
            if not resolved:
                return None
            ip_addr  = resolved[4][0]
            url_ip   = f"http://{ip_addr}"
            response = sess.get(
                url_ip, timeout=5, verify=False, allow_redirects=True,
                headers={"User-Agent": self.ua.random, "Host": f"www.{domain}"})
            if response.status_code < 400:
                rp       = urlparse(response.url)
                final    = f"{rp.scheme}://www.{domain}{rp.path}"
                if rp.query:
                    final += f"?{rp.query}"
                self.cache_manager.save_reverse_cache(cache_key, final, 'base')
                return final
        except Exception:
            pass
        return None

    def check_rsd_xml(self, domain, session=None):
        sess  = session or self.session
        paths = ['/rsd.xml', '/blog/rsd.xml', '/news/rsd.xml', '/blog1/rsd.xml',
                 '/diary/rsd.xml', '/mt/rsd.xml', '/kanri/rsd.xml']
        base_url = self.get_base_url_with_www(domain, session=sess)
        if not base_url:
            return None, None
        parsed      = urlparse(base_url)
        base_domain = parsed.netloc
        protocol    = parsed.scheme

        rsd_ip = None
        try:
            _r = _dns_resolve_with_timeout(base_domain)
            if _r:
                rsd_ip = _r[4][0]
        except Exception:
            pass

        for path in paths:
            try:
                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random
                url = f"{protocol}://{base_domain}{path}"
                if rsd_ip:
                    url_ip  = f"{protocol}://{rsd_ip}{path}"
                    headers["Host"] = base_domain
                    response = sess.get(url_ip, headers=headers,
                                        timeout=Config.TIMEOUT_SCAN,
                                        verify=False, allow_redirects=False)
                else:
                    response = sess.get(url, headers=headers,
                                        timeout=Config.TIMEOUT_SCAN,
                                        verify=False, allow_redirects=False)
                if response.status_code == 200 and 'rsd' in response.text.lower():
                    return response.text, url
            except Exception:
                continue
        return None, None

    def extract_mt_info(self, rsd_content):
        info = {'engine': None, 'api_link': None, 'version': None}
        em   = re.search(r'<engineName>(.+?)</engineName>', rsd_content, re.IGNORECASE)
        if em:
            info['engine'] = em.group(1)
            if 'movable type' in info['engine'].lower():
                vm = re.search(r'(\d+\.\d+)', info['engine'])
                if vm:
                    info['version'] = vm.group(1)
        am = re.search(r'<api[^>]*apiLink="([^"]+)"[^>]*>', rsd_content, re.IGNORECASE)
        if am:
            info['api_link'] = am.group(1).strip()
        return info

    def check_mt_endpoints(self, domain, mt_info, session=None):
        sess     = session or self.session
        results  = []
        if not mt_info['api_link']:
            return results

        xmlrpc_urls = []
        if mt_info['api_link'].startswith('http'):
            xmlrpc_urls.append(mt_info['api_link'])
        else:
            base_url = self.get_base_url_with_www(domain, session=sess)
            if base_url:
                p = urlparse(base_url)
                xmlrpc_urls.append(f"{p.scheme}://{p.netloc}{mt_info['api_link']}")

        resolved_map = {}
        for u in xmlrpc_urls:
            try:
                p  = urlparse(u)
                _r = _dns_resolve_with_timeout(p.netloc)
                if _r:
                    resolved_map[u] = (_r[4][0], p.netloc)
            except Exception:
                pass

        for xmlrpc_url in xmlrpc_urls:
            try:
                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random
                if xmlrpc_url in resolved_map:
                    ip, host_hdr = resolved_map[xmlrpc_url]
                    p       = urlparse(xmlrpc_url)
                    url_ip  = f"{p.scheme}://{ip}{p.path}"
                    headers["Host"] = host_hdr
                    response = sess.get(url_ip, headers=headers,
                                        timeout=Config.TIMEOUT_SCAN,
                                        allow_redirects=False, verify=False)
                else:
                    response = sess.get(xmlrpc_url, headers=headers,
                                        timeout=Config.TIMEOUT_SCAN,
                                        allow_redirects=False, verify=False)

                is_v4 = mt_info.get('version') and mt_info['version'].startswith('4')
                if response.status_code in [403, 411, 405]:
                    url_key = f"{xmlrpc_url}|{response.status_code}"
                    with self.lock:
                        if url_key not in self.found_urls:
                            self.found_urls[url_key] = True
                            self.found_urls.move_to_end(url_key)
                            while len(self.found_urls) > self.found_urls_max:
                                self.found_urls.popitem(last=False)
                            with open(self.output_files['movable_type'], 'a') as f:
                                f.write(f"{xmlrpc_url}\n")
                            if self.main:
                                self.main.increment_mt()
                            print(f"\n[+] MT: {xmlrpc_url.replace('http://','').replace('https://','')} "
                                  f"({response.status_code})")
                            results.append({'domain': domain, 'xmlrpc_url': xmlrpc_url,
                                            'xmlrpc_status': response.status_code,
                                            'version': mt_info.get('version'), 'is_v4': is_v4})

                if is_v4 and 'mt-xmlrpc.cgi' in xmlrpc_url:
                    upgrade_url = xmlrpc_url.replace('mt-xmlrpc.cgi', 'mt-upgrade.cgi')
                    if upgrade_url != xmlrpc_url:
                        try:
                            ur = sess.get(upgrade_url, headers=headers,
                                          timeout=Config.TIMEOUT_SCAN,
                                          allow_redirects=False, verify=False)
                            if ur.status_code == 200:
                                ukey = f"{upgrade_url}|200"
                                with self.lock:
                                    if ukey not in self.found_urls:
                                        self.found_urls[ukey] = True
                                        self.found_urls.move_to_end(ukey)
                                        while len(self.found_urls) > self.found_urls_max:
                                            self.found_urls.popitem(last=False)
                                        with open(self.output_files['movable_type_v4'], 'a') as f:
                                            f.write(f"{upgrade_url}\n")
                                        if self.main:
                                            self.main.increment_mtv4()
                                        print(f"\n[!] MT v4 upgrade.cgi: "
                                              f"{upgrade_url.replace('http://','').replace('https://','')}")
                        except Exception:
                            pass
            except Exception:
                continue
        return results

    def scan_domain(self, domain, session=None):
        try:
            rsd_content, rsd_url = self.check_rsd_xml(domain, session=session)
            if rsd_content:
                mt_info = self.extract_mt_info(rsd_content)
                if mt_info['engine'] and 'movable type' in mt_info['engine'].lower():
                    return self.check_mt_endpoints(domain, mt_info, session=session)
        except Exception:
            pass
        return []

    # ── process_ip: full pipeline dengan semua perlindungan ──
    def process_ip(self, ip):
        if self.cache_manager.is_ip_processed(ip):
            print(f"[↺] Skipping cached IP: {ip}")
            return

        print(f"\n[*] Processing IP: {ip}")
        # [BUG-3 FIX] activate() harus dipanggil sebelum tick() bisa berjalan.
        # HangWatchdog._active = False by default; tick() return early jika tidak aktif.
        # activate() belum pernah dipanggil dari mana pun → semua tick() adalah no-op,
        # watchdog efektif tidak berjalan meski thread-nya hidup.
        self._watchdog.activate()
        self._watchdog.tick(f"process_ip:start:{ip}")

        ip_start = time.time()

        # Step 1: Reverse IP lookup
        domains_ht = self.reverse_ip_hackertarget(ip)
        all_domains = domains_ht

        if not all_domains:
            self.cache_manager.mark_ip_processed(ip, 'empty')
            print(f"[-] No domains for IP {ip} "
                  f"(negative cache {Config.NEGATIVE_CACHE_TTL//3600}h)", flush=True)
            return

        print(f"[+] Total domains: {len(all_domains)} (HT: {len(domains_ht)})")
        self._watchdog.tick(f"process_ip:got_domains:{ip}:{len(all_domains)}")

        # [FIX-7] Tunggu jika proxy sedang refresh sebelum mulai domain scan.
        # Tujuan: proxy refresh tidak memotong domain batch yang sedang berjalan.
        self.proxy_manager.wait_if_refreshing(timeout=30)

        # Step 2: Domain scan dengan perlindungan
        found_count    = 0
        failed_domains = []   # [FIX-9] domain yang gagal akan di-retry

        # [FIX-6] context manager: pause cache cleanup selama domain scan
        with self.cache_manager.scan_domain_in_progress():
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_SCAN) as executor:

                def _scan_with_session(domain):
                    sess = requests.Session()
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=1, pool_maxsize=1,
                        max_retries=0, pool_block=False)
                    sess.mount('http://',  adapter)
                    sess.mount('https://', adapter)
                    try:
                        return domain, self.scan_domain(domain, session=sess)
                    except Exception as e:
                        return domain, None   # None = perlu retry
                    finally:
                        sess.close()

                futures = {executor.submit(_scan_with_session, d): d
                           for d in all_domains}

                # BUGFIX: as_completed(timeout=N) melempar TimeoutError di luar
                # try/except (dari for-statement itu sendiri) kalau ada 1 future
                # yang lambat → crash "N futures unfinished".
                # Tidak perlu timeout di sini karena setiap domain sudah dibatasi
                # oleh per-request timeout (TIMEOUT_SCAN=10s) dan DNS timeout (4s).
                # _scan_with_session sudah catch semua Exception → future.result()
                # tidak akan raise, jadi timeout di result() juga tidak diperlukan.
                for future in as_completed(futures):
                    domain = futures[future]
                    try:
                        _, results = future.result()
                        if results is None:
                            # _scan_with_session return None jika exception internal
                            failed_domains.append(domain)
                        elif results:
                            found_count += len(results)
                            self._watchdog.tick(f"process_ip:found_mt:{ip}:{domain}")
                    except Exception:
                        # Fallback — seharusnya tidak pernah kena karena
                        # _scan_with_session sudah wrap semua exception
                        failed_domains.append(domain)

        # [FIX-9] Retry domain yang gagal / timeout (satu kali, sequential, session baru)
        if failed_domains:
            print(f"[~] Retrying {len(failed_domains)} domain yang gagal dari IP {ip}...",
                  flush=True)
            for domain in failed_domains:
                self._watchdog.tick(f"process_ip:retry_domain:{ip}:{domain}")
                try:
                    results = self.scan_domain(domain)
                    if results:
                        found_count += len(results)
                except Exception:
                    pass

        elapsed = time.time() - ip_start
        print(f"[+] IP {ip}: {found_count} MT found | {len(all_domains)} domains | "
              f"{elapsed:.1f}s | {len(failed_domains)} retried", flush=True)

        status = 'success' if found_count else 'empty'
        self.cache_manager.mark_ip_processed(ip, status)
        self._watchdog.tick(f"process_ip:done:{ip}:{status}")
