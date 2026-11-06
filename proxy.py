#!/usr/bin/env python3
"""
gologin_farm_api.py — farm akun GoLogin tanpa browser (requests murni).

Alur per akun:
  mailbox mail.tm/mail.gw (REST) -> signup tokenless -> (solve turnstile bila ditolak)
  -> login -> ambil token -> konfirmasi email -> buat profil proxy mode 'gologin'

Contoh:
  python gologin_farm_api.py --probe
  python gologin_farm_api.py --count 1 --no-env-proxy
  python gologin_farm_api.py --count 3 --region us --solver local --prefetch 2
  python gologin_farm_api.py --count 3 --region us --solver capsolver
"""

import argparse, json, os, queue, random, re, string, sys, threading, time
from datetime import datetime
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API = "https://api.gologin.com"
SIGNUP_URL = "https://app.gologin.com/sign_up"
PASSWORD = "123456678"
REGIONS = ["us", "ca", "uk", "de", "in"]

RESULTS = Path("gologin_results_api.jsonl")
MAIL_BASES = ["https://api.mail.tm", "https://api.mail.gw"]

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/138.0.0.0 Safari/537.36")

SIGNUP_CANDIDATES = [
    f"{API}/user",
    f"{API}/user/signup",
    f"{API}/signup",
    f"{API}/register",
    "https://app.gologin.com/api/user",
    "https://app.gologin.com/api/signup",
]

LOGIN_CANDIDATES = [
    f"{API}/user/login",
    f"{API}/user/auth",
    f"{API}/login",
]

CONFIRM_CANDIDATES = [
    ("GET", f"{API}/user/confirm", "params"),
    ("POST", f"{API}/user/confirm", "json"),
    ("POST", f"{API}/user/confirm_email", "json"),
    ("GET", "https://app.gologin.com/api/confirm_email", "params"),
]

TOKEN_KEYS = ("token", "accessToken", "access_token", "jwt", "idToken")
SITEKEY_RE = re.compile(
    r'(?:data-sitekey=["\']|sitekey["\']?\s*[:=]\s*["\'])(0x[0-9A-Za-z_\-]{10,})')
CAPTCHA_HINT = re.compile(r"turnstile|captcha|recaptcha|challenge", re.I)

# diisi dari argumen CLI di main()
USE_ENV_PROXY = True
PROXY_URL = None
S = None

TOKENS = queue.Queue()


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def jitter(a=0.6, b=1.8):
    time.sleep(random.uniform(a, b))


# ---------------- http ----------------

def make_session():
    """Session dengan retry untuk connection reset / 5xx."""
    s = requests.Session()
    s.trust_env = USE_ENV_PROXY
    if PROXY_URL:
        s.proxies = {"http": PROXY_URL, "https": PROXY_URL}
        s.trust_env = False
    retry = Retry(
        total=4, connect=4, read=3, status=3,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH", "DELETE"]),
        raise_on_status=False,
    )
    ad = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("https://", ad)
    s.mount("http://", ad)
    s.headers.update({"User-Agent": UA, "Content-Type": "application/json",
                      "Accept": "application/json"})
    return s


def sess():
    global S
    if S is None:
        S = make_session()
    return S


def headers(extra=None):
    h = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://app.gologin.com",
        "Referer": SIGNUP_URL,
        "Content-Type": "application/json",
        "sec-ch-ua": '"Chromium";v="138", "Not=A?Brand";v="24", "Google Chrome";v="138"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
    }
    if extra:
        h.update(extra)
    return h


def auth_headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
            "User-Agent": UA}


def first_link(blob, needle="gologin"):
    urls = [u.replace("&amp;", "&")
            for u in re.findall(r"https?://[^\s\"'<>\\]+", blob or "")]
    urls = [u for u in urls if "unsubscribe" not in u.lower()]
    for u in urls:
        if needle in u:
            return u
    for u in urls:
        if re.search(r"confirm|verify|activat|token", u, re.I):
            return u
    return urls[0] if urls else None


def needs_captcha(r):
    return r is not None and (r.status_code in (400, 403, 422)
                              or bool(CAPTCHA_HINT.search(r.text or "")))


# ---------------- mailbox: mail.tm / mail.gw REST ----------------

class MailBox:
    def __init__(self, bases=MAIL_BASES):
        self.bases = list(bases)
        self.s = None
        self.base = None
        self.addr = None
        self.token = None

    def open(self):
        for base in self.bases:
            try:
                self._open_on(base)
                log(f"  mailbox host: {base}")
                return self.addr
            except Exception as e:
                log(f"  mailbox {base} gagal: {type(e).__name__}: {e}")
        raise RuntimeError("semua host mailbox gagal")

    def _open_on(self, base):
        s = make_session()
        doms = [d.get("domain") for d in
                (s.get(f"{base}/domains", timeout=25).json() or {}).get("hydra:member", [])]
        doms = [d for d in doms if d]
        if not doms:
            raise RuntimeError("tanpa domain")
        for _ in range(6):
            addr = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
            addr = f"{addr}@{random.choice(doms)}"
            pw = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            r = s.post(f"{base}/accounts", json={"address": addr, "password": pw}, timeout=25)
            if not r.ok:
                continue
            t = s.post(f"{base}/token", json={"address": addr, "password": pw}, timeout=25)
            if not t.ok:
                continue
            tok = (t.json() or {}).get("token")
            if tok:
                self.s, self.base, self.addr, self.token = s, base, addr, tok
                return
        raise RuntimeError("gagal buat mailbox")

    def messages(self):
        r = self.s.get(f"{self.base}/messages?page=1",
                       headers={"Authorization": f"Bearer {self.token}"}, timeout=25)
        return (r.json() or {}).get("hydra:member", []) if r.ok else []

    def body(self, mid):
        r = self.s.get(f"{self.base}/messages/{mid}",
                       headers={"Authorization": f"Bearer {self.token}"}, timeout=25)
        if not r.ok:
            return ""
        j = r.json() or {}
        parts = [j.get("subject") or ""]
        for key in ("html", "text"):
            v = j.get(key) or []
            parts.extend(v if isinstance(v, list) else [v])
        return "\n".join(p for p in parts if p)

    def wait_for_link(self, timeout=240, needle="gologin"):
        deadline = time.time() + timeout
        seen = set()
        while time.time() < deadline:
            try:
                for m in self.messages():
                    mid = m.get("id")
                    if mid in seen:
                        continue
                    blob = self.body(mid)
                    if not blob.strip():
                        continue
                    seen.add(mid)
                    link = first_link(blob, needle)
                    if link:
                        return link
            except Exception as e:
                log(f"  inbox err: {e}")
            time.sleep(4)
        return None


# ---------------- turnstile ----------------

def sitekey():
    try:
        r = sess().get(SIGNUP_URL, headers={"User-Agent": UA}, timeout=45)
        m = SITEKEY_RE.search(r.text or "")
        return m.group(1) if m else None
    except Exception:
        return None


def solve(solver, key, sk, url=SIGNUP_URL, timeout=150):
    if solver == "local":
        return solve_local(url, sk, key or "http://127.0.0.1:5000", timeout)
    if not (solver and key and sk):
        return None
    log(f"  solver={solver} sitekey={sk[:12]}...")
    if solver == "capsolver":
        r = sess().post("https://api.capsolver.com/createTask", json={
            "clientKey": key,
            "task": {"type": "AntiTurnstileTaskProxyLess",
                     "websiteURL": url, "websiteKey": sk}}, timeout=60)
        tid = (r.json() or {}).get("taskId")
        if not tid:
            log(f"  solver create gagal: {r.text[:160]}")
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(3)
            q = sess().post("https://api.capsolver.com/getTaskResult",
                            json={"clientKey": key, "taskId": tid}, timeout=45).json() or {}
            if q.get("status") == "ready":
                sol = q.get("solution") or {}
                return sol.get("token") or sol.get("gRecaptchaResponse")
            if q.get("status") == "failed":
                return None
        return None
    if solver == "2captcha":
        r = sess().post("https://2captcha.com/in.php", data={
            "key": key, "method": "turnstile", "sitekey": sk,
            "pageurl": url, "json": 1}, timeout=60).json() or {}
        if r.get("status") != 1:
            return None
        rid = r["request"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(5)
            q = sess().get("https://2captcha.com/res.php", params={
                "key": key, "action": "get", "id": rid, "json": 1}, timeout=45).json() or {}
            if q.get("status") == 1:
                return q.get("request")
            if q.get("request") != "CAPCHA_NOT_READY":
                return None
        return None
    return None


def solve_local(url, sk, base, timeout):
    """Backend Theyka/Turnstile-Solver di localhost — tanpa key."""
    if not sk:
        return None
    try:
        r = sess().post(f"{base}/turnstile", json={"url": url, "sitekey": sk}, timeout=30)
        if not r.ok:
            r = sess().post(f"{base}/turnstile", params={"url": url, "sitekey": sk},
                            timeout=30)
        j = r.json() or {}
    except Exception as e:
        log(f"  solver lokal err: {type(e).__name__}: {e}")
        return None
    tok = j.get("token") or j.get("value")
    if tok:
        return tok
    tid = j.get("taskId") or j.get("id")
    if not tid:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        try:
            q = sess().get(f"{base}/result", params={"id": tid}, timeout=20).json() or {}
        except Exception:
            continue
        v = q.get("value") or q.get("token") or q.get("solution")
        if isinstance(v, dict):
            v = v.get("token")
        if v:
            return v
        if q.get("status") in ("failed", "error"):
            return None
    return None


def take_token():
    try:
        return TOKENS.get_nowait()
    except queue.Empty:
        return None


def start_prefetch(solver, key, sk, size):
    def worker():
        while True:
            try:
                t = solve(solver, key, sk)
                if t:
                    TOKENS.put(t)
            except Exception:
                pass
            time.sleep(1)

    for _ in range(size):
        threading.Thread(target=worker, daemon=True).start()
    log(f"  prefetch {size} worker aktif")


# ---------------- signup / login / confirm ----------------

def try_signup(email, turnstile):
    payload = {"email": email, "password": PASSWORD, "plan": "free"}
    if turnstile:
        payload.update({"turnstileToken": turnstile,
                        "cfTurnstileResponse": turnstile,
                        "g-recaptcha-response": turnstile})
    last = None
    for url in SIGNUP_CANDIDATES:
        try:
            r = sess().post(url, headers=headers(), json=payload, timeout=60)
        except Exception as e:
            log(f"  signup {url} -> err {type(e).__name__}: {e}")
            continue
        last = r
        log(f"  signup {url} -> {r.status_code} {(r.text or '')[:150]}")
        if r.status_code in (200, 201) and not re.search(
                r'"error"|"message":"(invalid|already)', r.text or "", re.I):
            return url, r
    return None, last


def extract_token(obj, depth=0):
    if depth > 4:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in TOKEN_KEYS and isinstance(v, str) and len(v) >= 30:
                return v
        for v in obj.values():
            t = extract_token(v, depth + 1)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj:
            t = extract_token(v, depth + 1)
            if t:
                return t
    return None


def login(email, verbose=True):
    for body in ({"username": email, "password": PASSWORD},
                 {"email": email, "password": PASSWORD}):
        for url in LOGIN_CANDIDATES:
            try:
                r = sess().post(url, headers=headers(), json=body, timeout=45)
            except Exception:
                continue
            if verbose:
                log(f"  login {url} {list(body)[0]} -> {r.status_code}")
            if r.ok:
                tok = extract_token(r.json() if r.text else {})
                if tok:
                    return tok
    return None


def confirm(link):
    log(f"  GET konfirmasi: {link[:90]}")
    try:
        r = sess().get(link, headers={"User-Agent": UA}, timeout=60,
                       allow_redirects=True)
        log(f"  -> {r.status_code} {r.url[:90]}")
        final = r.url
    except Exception as e:
        log(f"  GET konfirmasi err: {type(e).__name__}: {e}")
        final = link
    m = re.search(r"[?&]token=([A-Za-z0-9._\-]+)", final) or \
        re.search(r"[?&]token=([A-Za-z0-9._\-]+)", link)
    if not m:
        return False
    tok = m.group(1)
    for method, url, kind in CONFIRM_CANDIDATES:
        try:
            rr = sess().request(method, url, headers=headers(), timeout=45,
                                **{kind: {"token": tok}})
        except Exception:
            continue
        log(f"  confirm {method} {url.rsplit('/', 1)[-1]} -> {rr.status_code}")
        if rr.ok and "error" not in (rr.text or "").lower()[:200]:
            return True
    return False


# ---------------- profil proxy ----------------

def create_profile_with_proxy(token, region):
    h = auth_headers(token)
    body = {"os": "win", "proxy": {"mode": "gologin", "autoProxyRegion": region}}
    r = sess().post(f"{API}/browser/quick", headers=h, json=body, timeout=60)
    if r.ok:
        p = r.json() or {}
        return p.get("id"), p.get("proxy") or {}
    r = sess().post(f"{API}/browser/custom", headers=h,
                    json={"os": "win", "proxy": body["proxy"]}, timeout=60)
    if not r.ok:
        raise RuntimeError(f"create profile gagal {r.status_code}: {r.text[:250]}")
    pid = (r.json() or {}).get("id")
    if not pid:
        return None, {}
    g = sess().get(f"{API}/browser/{pid}", headers=h, timeout=60)
    return pid, (((g.json() or {}).get("proxy")) or {}) if g.ok else {}


def save(rec):
    with RESULTS.open("a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------- preflight / probe ----------------

def preflight():
    log(f"env proxy: {'AKTIF (trust_env)' if USE_ENV_PROXY else 'dimatikan'}"
        f"{' via ' + PROXY_URL if PROXY_URL else ''}")
    for u in ("https://api.mail.tm/domains", "https://api.mail.gw/domains",
              "https://api.gologin.com/user"):
        t0 = time.time()
        try:
            r = sess().get(u, timeout=20)
            log(f"  preflight {u} -> {r.status_code} ({int((time.time() - t0) * 1000)} ms)")
        except Exception as e:
            log(f"  preflight {u} -> GAGAL {type(e).__name__}: {e}")


def probe():
    sk = sitekey()
    log(f"sitekey terdeteksi: {sk or 'TIDAK ADA (cek manual di source halaman)'}")
    log("kandidat signup (tanpa turnstile):")
    for url in SIGNUP_CANDIDATES:
        try:
            r = sess().post(url, headers=headers(),
                            json={"email": "probe@example.com", "password": PASSWORD},
                            timeout=45)
            tag = " <-- butuh turnstile" if needs_captcha(r) else ""
            log(f"  {r.status_code} {url} :: {(r.text or '')[:120]}{tag}")
        except Exception as e:
            log(f"  ERR {url} :: {type(e).__name__}: {e}")
    log("kandidat login:")
    for url in LOGIN_CANDIDATES:
        try:
            r = sess().post(url, headers=headers(),
                            json={"username": "probe@example.com", "password": PASSWORD},
                            timeout=45)
            log(f"  {r.status_code} {url} :: {(r.text or '')[:120]}")
        except Exception as e:
            log(f"  ERR {url} :: {type(e).__name__}: {e}")


# ---------------- main ----------------

def run_one(region, solver, solver_key, solver_url, skey, mail_timeout, need_confirm):
    mail = MailBox()
    email = mail.open()
    log(f"akun: {email}")

    # 1) coba tanpa token dulu — jalur tercepat
    url, resp = try_signup(email, None)

    # 2) hanya solve kalau memang ditolak captcha
    if not url and solver and needs_captcha(resp):
        ts = take_token()
        if not ts:
            log("  perlu token, solve...")
            ts = solve(solver, solver_key or solver_url, skey)
        if ts:
            url, resp = try_signup(email, ts)

    if not url:
        reason = " (turnstile)" if needs_captcha(resp) else ""
        log(f"  SIGNUP gagal{reason} — jalankan --probe / pakai versi browser")
        save({"email": email, "password": PASSWORD, "token": None,
              "proxy": None, "ts": datetime.now().isoformat()})
        return

    token = login(email, verbose=False)
    if not token and need_confirm:
        link = mail.wait_for_link(timeout=mail_timeout)
        if link:
            confirm(link)
            token = login(email)

    if not token:
        log("  TIDAK dapat token")
        save({"email": email, "password": PASSWORD, "token": None,
              "proxy": None, "ts": datetime.now().isoformat()})
        return

    log(f"  token ok ({token[:12]}...)")
    me = sess().get(f"{API}/user", headers=auth_headers(token), timeout=30)
    log(f"  /user -> {me.status_code}")
    if me.ok:
        d = me.json() or {}
        log(f"  plan={d.get('plan') or d.get('tariff')} "
            f"proxy_traffic={d.get('proxyTraffic') or d.get('trafficLeft')}")

    pid, proxy = create_profile_with_proxy(token, region)
    log(f"  profil {pid} proxy={proxy.get('mode')} "
        f"{proxy.get('host')}:{proxy.get('port')}")

    save({"email": email, "password": PASSWORD, "token": token,
          "profile_id": pid, "proxy": proxy, "ts": datetime.now().isoformat()})
    log("  tersimpan")


def main():
    global USE_ENV_PROXY, PROXY_URL, S

    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--region", default="us", choices=REGIONS)
    ap.add_argument("--solver", choices=["local", "capsolver", "2captcha"])
    ap.add_argument("--solver-url", default="http://127.0.0.1:5000")
    ap.add_argument("--prefetch", type=int, default=0,
                    help="jumlah token yang disiapkan paralel (<=3 aman)")
    ap.add_argument("--sitekey", default=None)
    ap.add_argument("--mail-timeout", type=int, default=240)
    ap.add_argument("--no-confirm", action="store_true",
                    help="lewati langkah konfirmasi email")
    ap.add_argument("--no-env-proxy", action="store_true",
                    help="abaikan https_proxy/http_proxy dari shell")
    ap.add_argument("--proxy", default=None,
                    help="paksa lewat proxy ini, mis. http://127.0.0.1:8080")
    ap.add_argument("--delay", type=int, default=15)
    ap.add_argument("--probe", action="store_true")
    a = ap.parse_args()

    USE_ENV_PROXY = not a.no_env_proxy
    PROXY_URL = a.proxy
    S = make_session()

    if a.probe:
        preflight()
        probe()
        return

    preflight()

    solver_key = None
    if a.solver in ("capsolver", "2captcha"):
        env = {"capsolver": "CAPSOLVER_KEY", "2captcha": "TWOCAPTCHA_KEY"}[a.solver]
        solver_key = os.environ.get(env, "").strip()
        if not solver_key:
            sys.exit(f"{env} kosong")

    sk = a.sitekey or sitekey()
    if a.solver and a.solver != "local" and not sk:
        sys.exit("sitekey tidak terdeteksi — isi manual dengan --sitekey")

    if a.solver and a.prefetch:
        start_prefetch(a.solver, solver_key or a.solver_url, sk, a.prefetch)

    for i in range(1, a.count + 1):
        log(f"=== akun {i}/{a.count} (region {a.region}) ===")
        try:
            run_one(a.region, a.solver, solver_key, a.solver_url, sk,
                    a.mail_timeout, not a.no_confirm)
        except Exception as e:
            log(f"  GAGAL: {type(e).__name__}: {e}")
        if i < a.count:
            time.sleep(a.delay)

    log(f"selesai. hasil: {RESULTS.resolve()}")


if __name__ == "__main__":
    main()
