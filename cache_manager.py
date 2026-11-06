# cache_manager.py - FIXED VERSION
# Fixes applied:
#   [FIX-1] threading.Lock -> RLock: _ops_maybe_purge dipanggil di dalam
#           with self.lock: dan juga mengakuisisi self.lock -> DEADLOCK tiap 5000 ops
#   [FIX-2] _writeback_locked: guard KeyError untuk dirty keys yang sudah di-evict LRU
#   [FIX-3] _ops_maybe_purge: discard dirty set saat evict stale agar writeback tidak crash
#   [FIX-4] clear_all_cache: VACUUM dipindah ke luar with self.lock (long op block semua)
#   [FIX-5] HangWatchdog: monitor aktivitas, alert + tindakan kalau stuck
#   [FIX-6] scan_domain_in_progress(): context manager pause cleanup saat domain scan aktif

import sqlite3
import json
import time
import os
import threading
import shutil
from collections import OrderedDict
from config import Config


# ─────────────────────────────────────────────────────────
#  HANG WATCHDOG
# ─────────────────────────────────────────────────────────
class HangWatchdog:
    """Monitor aktivitas global. Jika tidak ada progress dalam ALERT_THRESHOLD
    detik, cetak peringatan. Jika melebihi KILL_THRESHOLD, set recovery_needed."""

    ALERT_THRESHOLD = getattr(Config, 'HANG_ALERT_THRESHOLD', 120)   # 2 menit
    KILL_THRESHOLD  = getattr(Config, 'HANG_KILL_THRESHOLD',  300)   # 5 menit

    def __init__(self):
        self._last_tick  = time.time()
        self._lock       = threading.Lock()
        self._active     = False   # [FIX-5b] watchdog hanya jalan saat scan aktif
        self.recovery_needed = threading.Event()
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def activate(self):
        """[FIX-5b] Aktifkan watchdog hanya saat scan benar-benar berjalan.
        Sebelum dipanggil, watchdog thread idle dan tidak akan trigger alert."""
        with self._lock:
            self._active    = True
            self._last_tick = time.time()
            self._label     = ''

    def tick(self, label=''):
        """Dipanggil tiap ada progress nyata (IP diproses, domain ditemukan, dll)."""
        with self._lock:
            if not self._active:
                return
            self._last_tick = time.time()
            self._label = label
        self.recovery_needed.clear()

    def _monitor(self):
        prev_label = ''
        while True:
            time.sleep(30)
            with self._lock:
                if not self._active:
                    prev_label = ''
                    continue
                elapsed = time.time() - self._last_tick
                label   = getattr(self, '_label', '')
            if elapsed >= self.KILL_THRESHOLD:
                print(f"\n[‼] HANG WATCHDOG: tidak ada progress selama "
                      f"{elapsed:.0f}s (last: {label}) — menandai recovery_needed",
                      flush=True)
                self.recovery_needed.set()
            elif elapsed >= self.ALERT_THRESHOLD:
                if label != prev_label or elapsed % 60 < 32:
                    print(f"\n[!] HANG WATCHDOG: tidak ada progress selama "
                          f"{elapsed:.0f}s (last: {label})", flush=True)
                prev_label = label
            else:
                prev_label = label


# Singleton watchdog — diakses oleh scanner dan cache_manager
_watchdog = HangWatchdog()


def get_watchdog() -> HangWatchdog:
    return _watchdog


# ─────────────────────────────────────────────────────────
#  THREAD-LOCAL DB
# ─────────────────────────────────────────────────────────
class _ThreadLocalDB:
    """Koneksi SQLite per-thread + WAL. Tidak pernah close selama proses."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.local   = threading.local()

    def conn(self):
        c = getattr(self.local, 'conn', None)
        if c is None:
            c = sqlite3.connect(self.db_path, timeout=30)
            cur = c.cursor()
            cur.execute('PRAGMA journal_mode=WAL')
            cur.execute('PRAGMA synchronous=NORMAL')
            cur.execute('PRAGMA temp_store=MEMORY')
            cur.execute('PRAGMA cache_size=-8192')
            self.local.conn = c
        return c

    def close_all(self):
        c = getattr(self.local, 'conn', None)
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self.local.conn = None


def _lru_purge(od: OrderedDict, max_size: int):
    while len(od) > max_size:
        od.popitem(last=False)


# ─────────────────────────────────────────────────────────
#  CACHE MANAGER
# ─────────────────────────────────────────────────────────
class CacheManager:
    def __init__(self):
        self.temp_dir           = self._get_full_temp_dir()
        self.db_path            = os.path.join(self.temp_dir, Config.OUTPUT_FILES['cache'])
        self.processed_ips_path = os.path.join(self.temp_dir, Config.OUTPUT_FILES['processed_ips'])

        # [FIX-1] RLock menggantikan Lock.
        # _ops_maybe_purge dipanggil dari dalam with self.lock: dan
        # di dalamnya juga ada with self.lock: → DEADLOCK tiap 5000 ops dengan Lock biasa.
        # RLock membolehkan thread yang sama untuk re-acquire lock yang sudah dipegangnya.
        self.lock = threading.RLock()

        self.db = _ThreadLocalDB(self.db_path)

        # L1 in-memory LRU
        self.l1_reverse          = OrderedDict()  # cache_key -> (domains, ts, source)
        self.l1_reverse_dirty    = set()           # belum write-back ke SQLite
        self.l1_processed        = OrderedDict()  # ip -> (ts, status)
        self._l1_processed_dirty = set()

        self._processed_file_buf  = []
        self._processed_file_lock = threading.Lock()
        self._ops_count           = 0

        # Counter domain scan aktif — pause cleanup saat ada scan berjalan
        self._domain_scan_active = 0
        self._domain_scan_lock   = threading.Lock()

        self.init_database()
        self._prewarm_l1()
        self.start_cleanup_thread()

    # ── context manager untuk domain scan ──────────────────
    class _ScanGuard:
        """with cache_manager.scan_domain_in_progress(): — pause cleanup berat."""
        def __init__(self, cm):
            self._cm = cm
        def __enter__(self):
            with self._cm._domain_scan_lock:
                self._cm._domain_scan_active += 1
        def __exit__(self, *_):
            with self._cm._domain_scan_lock:
                self._cm._domain_scan_active -= 1

    def scan_domain_in_progress(self):
        return self._ScanGuard(self)

    def _is_scan_active(self):
        with self._domain_scan_lock:
            return self._domain_scan_active > 0

    # ── helpers ────────────────────────────────────────────
    def _get_full_temp_dir(self):
        temp_dir = os.path.abspath(os.path.expanduser(Config.TEMP_DIR))
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir

    def init_database(self):
        Config.ensure_temp_dir()
        os.makedirs(self.temp_dir, exist_ok=True)
        conn   = self.db.conn()
        cursor = conn.cursor()
        cursor.execute('PRAGMA foreign_keys = ON')
        cursor.execute('PRAGMA auto_vacuum = 0')
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA synchronous=NORMAL')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reverse_ip_cache (
                ip TEXT PRIMARY KEY, domains TEXT, timestamp REAL, source TEXT)''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                domain TEXT PRIMARY KEY, result TEXT, timestamp REAL)''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_ips (
                ip TEXT PRIMARY KEY, timestamp REAL, status TEXT)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp    ON reverse_ip_cache(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_proc_timestamp ON processed_ips(timestamp)')
        conn.commit()
        print(f"[✓] Database initialized: {self.db_path} (WAL, per-thread conn, RLock)")

    # ── L1 purge & writeback ───────────────────────────────
    def _ops_maybe_purge(self):
        """Auto-purge tiap N ops. Aman dipanggil di dalam with self.lock (RLock)."""
        self._ops_count += 1
        if self._ops_count % Config.L1_PURGE_CHECK_INTERVAL != 0:
            return
        now = time.time()
        # RLock: re-acquire oleh thread yang sama adalah no-op (tidak deadlock)
        with self.lock:
            # [FIX-3] Saat buang stale, hapus juga dari dirty agar _writeback_locked
            # tidak mencoba l1_reverse[k] yang sudah tidak ada → KeyError
            stale = [k for k, (d, ts, s) in self.l1_reverse.items()
                     if now - ts > Config.REVERSE_CACHE_TTL]
            for k in stale:
                self.l1_reverse.pop(k, None)
                self.l1_reverse_dirty.discard(k)   # [FIX-3]

            stale_p = []
            for k, ent in self.l1_processed.items():
                ts, status = ent if isinstance(ent, tuple) else (ent, 'success')
                ttl = Config.NEGATIVE_CACHE_TTL if status == 'empty' else Config.PROCESSED_TTL
                if ttl > 0 and now - ts > ttl:
                    stale_p.append(k)
            for k in stale_p:
                self.l1_processed.pop(k, None)
                self._l1_processed_dirty.discard(k)

            _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
            _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)

            if (len(self.l1_reverse_dirty)    >= Config.L1_WRITEBACK_BATCH or
                    len(self._l1_processed_dirty) >= Config.L1_WRITEBACK_BATCH):
                self._writeback_locked()

        if stale:
            print(f"[~] L1 purge: {len(stale)} stale, "
                  f"rev={len(self.l1_reverse)} proc={len(self.l1_processed)}")

    def _writeback_locked(self, _now=None):
        """Write dirty L1 → SQLite. Dipanggil dengan self.lock sudah dipegang."""
        try:
            conn = self.db.conn()
            cur  = conn.cursor()

            if self.l1_reverse_dirty:
                # [FIX-2] Guard KeyError: skip key yang sudah di-evict LRU tapi
                # masih ada di dirty_set (LRU purge tidak menghapus dari dirty set).
                rows = []
                for k in list(self.l1_reverse_dirty):
                    if k in self.l1_reverse:
                        d, ts, s = self.l1_reverse[k]
                        rows.append((k, json.dumps(d), ts, s))
                if rows:
                    cur.executemany(
                        'INSERT OR REPLACE INTO reverse_ip_cache '
                        '(ip, domains, timestamp, source) VALUES (?,?,?,?)',
                        rows)
                self.l1_reverse_dirty.clear()

            if self._l1_processed_dirty:
                rows_p = []
                for k in list(self._l1_processed_dirty):
                    if k in self.l1_processed:
                        ts, status = self.l1_processed[k]
                        rows_p.append((k, ts, status))
                if rows_p:
                    cur.executemany(
                        'INSERT OR REPLACE INTO processed_ips '
                        '(ip, timestamp, status) VALUES (?,?,?)',
                        rows_p)
                self._l1_processed_dirty.clear()

            conn.commit()
        except Exception as e:
            print(f"[-] Write-back error (data aman di L1, retry nanti): {e}")

    def _prewarm_l1(self):
        try:
            conn = self.db.conn()
            cur  = conn.cursor()
            cur.execute(
                "SELECT ip, domains, timestamp FROM reverse_ip_cache "
                "WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (time.time() - Config.REVERSE_CACHE_TTL, Config.L1_REVERSE_CACHE_MAX))
            for ip, dom, ts in cur.fetchall():
                try:
                    self.l1_reverse[ip] = (json.loads(dom), ts, '')
                except Exception:
                    pass
            _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)

            cur.execute(
                "SELECT ip, timestamp, status FROM processed_ips "
                "ORDER BY timestamp DESC LIMIT ?",
                (Config.L1_PROCESSED_MAX,))
            for ip, ts, status in cur.fetchall():
                self.l1_processed[ip] = (ts, (status or 'success'))
            _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
            print(f"[~] L1 prewarm: {len(self.l1_reverse)} reverse, "
                  f"{len(self.l1_processed)} processed")
        except Exception as e:
            print(f"[!] L1 prewarm error (lanjut tanpa prewarm): {e}")

    # ── public cache API ───────────────────────────────────
    def get_reverse_cache(self, ip):
        with self.lock:
            entri = self.l1_reverse.get(ip)
            if entri is not None:
                domains, ts, _src = entri
                self.l1_reverse.move_to_end(ip)
                if time.time() - ts < Config.REVERSE_CACHE_TTL:
                    self._ops_maybe_purge()
                    return domains
                self.l1_reverse.pop(ip, None)
                self.l1_reverse_dirty.discard(ip)
            self._ops_maybe_purge()
        try:
            cur = self.db.conn().cursor()
            cur.execute(
                'SELECT domains, timestamp FROM reverse_ip_cache WHERE ip = ?', (ip,))
            row = cur.fetchone()
            if row:
                domains, timestamp = row
                if time.time() - timestamp < Config.REVERSE_CACHE_TTL:
                    with self.lock:
                        self.l1_reverse[ip] = (json.loads(domains), timestamp, '')
                        self.l1_reverse.move_to_end(ip)
                        _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
                    return json.loads(domains)
        except Exception as e:
            print(f"[-] Error reading cache: {e}")
        return None

    def save_reverse_cache(self, ip, domains, source):
        with self.lock:
            now = time.time()
            self.l1_reverse[ip] = (list(domains) if domains else [], now, source)
            self.l1_reverse.move_to_end(ip)
            self.l1_reverse_dirty.add(ip)
            _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
            if len(self.l1_reverse_dirty) >= Config.L1_WRITEBACK_BATCH:
                self._writeback_locked()
            self._ops_maybe_purge()

    def is_ip_processed(self, ip):
        with self.lock:
            ent = self.l1_processed.get(ip)
            if ent is not None:
                ts, status = ent if isinstance(ent, tuple) else (ent, 'success')
                self.l1_processed.move_to_end(ip)
                ttl = Config.NEGATIVE_CACHE_TTL if status == 'empty' else Config.PROCESSED_TTL
                if ttl <= 0 or time.time() - ts < ttl:
                    return True
                self.l1_processed.pop(ip, None)
                self._l1_processed_dirty.discard(ip)
        try:
            cur = self.db.conn().cursor()
            cur.execute('SELECT timestamp, status FROM processed_ips WHERE ip = ?', (ip,))
            row = cur.fetchone()
            if row:
                ts, status = row[0], (row[1] or 'success')
                ttl = Config.NEGATIVE_CACHE_TTL if status == 'empty' else Config.PROCESSED_TTL
                if ttl <= 0 or time.time() - ts < ttl:
                    with self.lock:
                        self.l1_processed[ip] = (ts, status)
                        self.l1_processed.move_to_end(ip)
                        _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
                    return True
        except Exception as e:
            print(f"[-] Error checking processed IP: {e}")
        return False

    def mark_ip_processed(self, ip, status='success'):
        now = time.time()
        with self.lock:
            self.l1_processed[ip] = (now, status)
            self.l1_processed.move_to_end(ip)
            self._l1_processed_dirty.add(ip)
            _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
            self._processed_file_buf.append(ip)
            flush_file = len(self._processed_file_buf) >= Config.PROCESSED_FILE_FLUSH
            self._ops_maybe_purge()
            # [NO-REV-CACHE] buang entry reverse IP (key ht_) yang sudah di-
            # process/di-exploit — hasil tidak dipertahankan, selalu fresh.
            rev_key = f"ht_{ip}"
            if rev_key in self.l1_reverse:
                self.l1_reverse.pop(rev_key, None)
                self.l1_reverse_dirty.discard(rev_key)
        if flush_file:
            self._flush_processed_file()
        try:
            dbi = self.db.conn()
            dbi.execute('DELETE FROM reverse_ip_cache WHERE ip = ?', (f"ht_{ip}",))
            dbi.commit()
        except Exception as e:
            print(f"[-] buang reverse cache {ip} gagal: {e}")
        # Tick watchdog setiap IP di-mark
        _watchdog.tick(f"mark_ip_processed:{ip}:{status}")

    def _flush_processed_file(self):
        with self._processed_file_lock:
            if not self._processed_file_buf:
                return
            try:
                with open(self.processed_ips_path, 'a') as f:
                    f.write('\n'.join(self._processed_file_buf) + '\n')
            except Exception as e:
                print(f"[-] Error flushing processed_ips.txt: {e}")
                return
            self._processed_file_buf.clear()

    def flush_all(self):
        try:
            with self.lock:
                self._writeback_locked()
            self._flush_processed_file()
        except Exception as e:
            print(f"[-] flush_all error: {e}")

    # ── VACUUM guard ───────────────────────────────────────
    def _vacuum_with_guard(self, db_path, timeout=300):
        new_size_mb = 0.0
        try:
            vac_conn = sqlite3.connect(db_path, timeout=30)
            vac_cur  = vac_conn.cursor()
            t0 = time.time()
            vac_cur.execute('VACUUM')
            vac_conn.commit()
            vac_conn.close()
            new_size_mb = os.path.getsize(db_path) / (1024 * 1024)
            print(f"[✓] Auto vacuum: {new_size_mb:.1f}MB ({time.time()-t0:.1f}s)", flush=True)
            return ('ok', new_size_mb)
        except Exception as ve:
            print(f"[!] VACUUM error: {ve} (DB tetap jalan)", flush=True)
            return ('error', new_size_mb)

    # ── background cleanup ─────────────────────────────────
    def cleanup_old_cache(self):
        """Background cleanup thread."""
        VACUUM_TIMEOUT = 300
        while True:
            try:
                time.sleep(Config.CACHE_CLEANUP_INTERVAL)

                # [FIX-6] Jangan jalankan cleanup berat saat domain scan aktif —
                # tunggu sampai scan selesai (max 2 menit)
                wait_start = time.time()
                while self._is_scan_active():
                    if time.time() - wait_start > 120:
                        print("[!] cleanup: domain scan aktif > 2 menit, lanjut cleanup",
                              flush=True)
                        break
                    time.sleep(5)

                db_full_path = os.path.abspath(self.db_path)
                db_size      = (os.path.getsize(db_full_path) / (1024*1024)
                                if os.path.exists(db_full_path) else 0)

                conn   = self.db.conn()
                cursor = conn.cursor()
                cursor.execute('DELETE FROM reverse_ip_cache WHERE timestamp < ?',
                               (time.time() - Config.REVERSE_CACHE_TTL,))
                rev_count = cursor.rowcount
                cursor.execute('DELETE FROM processed_ips WHERE timestamp < ?',
                               (time.time() - 2592000,))
                proc_count = cursor.rowcount
                cursor.execute('DELETE FROM scan_results WHERE timestamp < ?',
                               (time.time() - 2592000,))
                scan_count = cursor.rowcount
                conn.commit()

                total_removed = rev_count + proc_count + scan_count
                if total_removed > 0:
                    print(f"[✓] Auto cleanup: {total_removed} entries removed "
                          f"(rev:{rev_count}, proc:{proc_count}, scan:{scan_count})")

                if db_size >= 50:
                    print(f"[i] DB {db_size:.1f}MB >= 50MB, VACUUM mulai (guard {VACUUM_TIMEOUT}s)...",
                          flush=True)
                    vac_result = None
                    t0 = time.time()
                    def _run_vacuum():
                        nonlocal vac_result
                        s, _ = self._vacuum_with_guard(db_full_path, timeout=VACUUM_TIMEOUT)
                        vac_result = s
                    vac_thread = threading.Thread(target=_run_vacuum, daemon=True)
                    vac_thread.start()
                    vac_thread.join(timeout=VACUUM_TIMEOUT + 60)
                    if vac_thread.is_alive():
                        print(f"[!] VACUUM stuck >{VACUUM_TIMEOUT+60}s, cleanup lanjut",
                              flush=True)
                    else:
                        print(f"[i] VACUUM selesai: {vac_result} ({time.time()-t0:.1f}s)",
                              flush=True)

                now = time.time()
                with self.lock:
                    for k in [k for k, (d, ts, s) in self.l1_reverse.items()
                              if now - ts > Config.REVERSE_CACHE_TTL]:
                        self.l1_reverse.pop(k, None)
                        self.l1_reverse_dirty.discard(k)
                    _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
                    for k, ent in list(self.l1_processed.items()):
                        ts, status = ent if isinstance(ent, tuple) else (ent, 'success')
                        ttl = (Config.NEGATIVE_CACHE_TTL if status == 'empty'
                               else Config.PROCESSED_TTL)
                        if ttl > 0 and now - ts > ttl:
                            self.l1_processed.pop(k, None)
                            self._l1_processed_dirty.discard(k)
                    _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
                    print(f"[~] L1 purged: rev={len(self.l1_reverse)} "
                          f"proc={len(self.l1_processed)}")
            except Exception as e:
                print(f"[-] Auto cleanup error: {e}")

    def close(self):
        try:
            self.flush_all()
        except Exception:
            pass
        try:
            c = getattr(self.db.local, 'conn', None)
            if c is not None:
                c.close()
                self.db.local.conn = None
        except Exception:
            pass

    def start_cleanup_thread(self):
        t = threading.Thread(target=self.cleanup_old_cache, daemon=True)
        t.start()
        print(f"[*] Cache cleanup thread started (interval: {Config.CACHE_CLEANUP_INTERVAL}s)")
        print(f"[*] Cache location: {self.temp_dir}")

    # ── stats & manual ops ────────────────────────────────
    def get_stats(self):
        try:
            conn   = self.db.conn()
            cursor = conn.cursor()
            stats  = {}
            for table in ['reverse_ip_cache', 'scan_results', 'processed_ips']:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[table] = cursor.fetchone()[0]
            stats['db_size_mb'] = (os.path.getsize(self.db_path) / (1024*1024)
                                   if os.path.exists(self.db_path) else 0)
            stats['db_path']     = os.path.abspath(self.db_path)
            stats['temp_dir']    = self.temp_dir
            stats['l1_reverse']  = len(self.l1_reverse)
            stats['l1_processed']= len(self.l1_processed)
            return stats
        except Exception as e:
            print(f"[-] Error getting stats: {e}")
            return {}

    def clear_all_cache(self):
        """Bersihkan semua cache. [FIX-4] VACUUM di luar lock."""
        try:
            with self.lock:
                conn   = self.db.conn()
                cursor = conn.cursor()
                cursor.execute('DELETE FROM reverse_ip_cache')
                cursor.execute('DELETE FROM scan_results')
                cursor.execute('DELETE FROM processed_ips')
                conn.commit()
                self.l1_reverse.clear()
                self.l1_reverse_dirty.clear()
                self.l1_processed.clear()
                self._l1_processed_dirty.clear()
                print(f"[✓] All cache cleared: {self.db_path} (L1 reset)")
        except Exception as e:
            print(f"[-] Error clearing cache: {e}")
            return False
        # [FIX-4] VACUUM di luar lock — long op tidak boleh hold lock
        try:
            conn   = self.db.conn()
            cursor = conn.cursor()
            cursor.execute('VACUUM')
            conn.commit()
        except Exception as e:
            print(f"[-] VACUUM after clear error: {e}")
        return True

    def optimize_database(self):
        try:
            conn   = self.db.conn()
            cursor = conn.cursor()
            cursor.execute('REINDEX')
            cursor.execute('VACUUM')
            cursor.execute('ANALYZE')
            print(f"[✓] Database optimized: {self.db_path}")
            return True
        except Exception as e:
            print(f"[-] Error optimizing database: {e}")
            return False

    def delete_database_file(self):
        try:
            if os.path.exists(self.db_path):
                size = os.path.getsize(self.db_path) / (1024*1024)
                os.remove(self.db_path)
                print(f"[✓] Database file deleted: {self.db_path} ({size:.2f} MB)")
                self.init_database()
                return True
        except Exception as e:
            print(f"[-] Error deleting database: {e}")
            return False
