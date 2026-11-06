# cleanup.py
import os
import shutil
import sqlite3
import time
from config import Config

def _get_db_path():
    """Kembalikan absolute path database cache (sesuai cache_manager.py)"""
    temp_dir = os.path.abspath(os.path.expanduser(Config.TEMP_DIR))
    return os.path.join(temp_dir, Config.OUTPUT_FILES['cache'])

def cleanup_temp_files():
    """Bersihkan file temporary dan optimasi database.
    
    Perbaikan bug sebelumnya:
    - rmtree di-jalankan SETELAH vacuum (sebelumnya: vacuum setelah rmtree → DB hilang)
    - listdir rekursif (shutil.disk_usage / walk) supaya subfolder tidak crash
    """
    print("[*] Cleaning up temporary files...")

    db_path = _get_db_path()
    temp_dir = os.path.dirname(db_path)

    # 1. Vacuum database dulu (kalau masih ada, supaya tidak terhapus sia-sia)
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            db_size_before = os.path.getsize(db_path) / (1024 * 1024)
            conn.execute('VACUUM')
            conn.close()
            db_size_after = os.path.getsize(db_path) / (1024 * 1024)
            print(f"[✓] Database optimized: {db_size_before:.2f} MB → {db_size_after:.2f} MB")
        except Exception as e:
            print(f"[!] Database vacuum error: {e}")
    else:
        print("[!] Database not found, skipping vacuum")

    # 2. Hapus temporary directory (rekursif, aman untuk subfolder)
    if os.path.exists(temp_dir):
        size = 0
        for dirpath, dirnames, filenames in os.walk(temp_dir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    size += os.path.getsize(fp)
                except OSError:
                    pass
        size_mb = size / (1024 * 1024)

        try:
            shutil.rmtree(temp_dir)
            print(f"[✓] Removed {temp_dir} ({size_mb:.2f} MB)")
        except Exception as e:
            print(f"[!] Failed to remove temp dir: {e}")

    # 3. Bersihkan output files lain di TEMP_DIR yang masih tersisa
    for fname in ['movable_type', 'movable_type_v4', 'processed_ips']:
        fpath = os.path.join(temp_dir, Config.OUTPUT_FILES.get(fname, ''))
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
                print(f"[✓] Removed {fpath}")
            except Exception as e:
                print(f"[!] Failed to remove {fpath}: {e}")


def cleanup_old_entries(days=7):
    """Hapus entries lama dari database (semua 3 tabel).
    
    Perbaikan bug sebelumnya:
    - Path DB sekarang pakai os.path.join + expanduser + abspath
    - Tambah DELETE untuk tabel scan_results (sebelumnya di-skip)
    - Hapus scan_results juga dengan interval 30 hari (seperti cache_manager.py)
    """
    db_path = _get_db_path()

    if not os.path.exists(db_path):
        print(f"[!] Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path, timeout=10)
    cursor = conn.cursor()

    # Cek tabel ada dulu (hindari error kalau DB kosong / belum di-init)
    tables = [row[0] for row in cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]

    rev_count = proc_count = scan_count = 0

    if 'reverse_ip_cache' in tables:
        cursor.execute(
            'DELETE FROM reverse_ip_cache WHERE timestamp < ?',
            (time.time() - (days * 86400),)
        )
        rev_count = cursor.rowcount

    if 'processed_ips' in tables:
        cursor.execute(
            'DELETE FROM processed_ips WHERE timestamp < ?',
            (time.time() - (days * 86400),)
        )
        proc_count = cursor.rowcount

    if 'scan_results' in tables:
        cursor.execute(
            'DELETE FROM scan_results WHERE timestamp < ?',
            (time.time() - (30 * 86400),)
        )
        scan_count = cursor.rowcount

    total_removed = rev_count + proc_count + scan_count
    conn.commit()

    # Vacuum kalau cukup banyak yang dihapus
    if total_removed > 100:
        cursor.execute('VACUUM')
        print(f"[✓] VACUUM executed after removing {total_removed} entries")

    conn.close()

    print(f"[✓] Removed {rev_count} reverse cache entries")
    print(f"[✓] Removed {proc_count} processed IP entries")
    print(f"[✓] Removed {scan_count} scan result entries")


if __name__ == "__main__":
    import time

    print("""
    ╔══════════════════════════════════════╗
    ║     Movable Type Scanner Cleanup     ║
    ╚══════════════════════════════════════╝
    """)

    db_path = _get_db_path()
    if os.path.exists(db_path):
        db_size = os.path.getsize(db_path) / (1024 * 1024)
        print(f"[*] Database: {db_path} ({db_size:.2f} MB)")
    else:
        print(f"[!] Database not found: {db_path}")

    print()
    print("1. Clean all temporary files (hapus temp dir + vacuum)")
    print("2. Clean entries older than 7 days (30 hari untuk scan_results)")
    print("3. Both")

    choice = input("\nChoice: ").strip()

    if choice in ['1', '3']:
        cleanup_temp_files()

    if choice in ['2', '3']:
        cleanup_old_entries()

    print("\n[✓] Cleanup completed")
