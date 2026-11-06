#!/usr/bin/env python3
"""
superbot.gg API key farm — inbox tempy lewat HTTP langsung
==========================================================

Per akun:
  1. POST tempy /api/inbox/create        -> alamat inbox baru (tanpa akun, tanpa key)
  2. POST tempy /api/inbox/extend        -> masa inbox 1 jam
  3. POST superbot /auth/email/start     -> superbot kirim kode ke alamat itu
  4. poll tempy /api/inbox/messages      -> baca email, ambil kodenya
  5. POST superbot /auth/email/verify    -> token sbk_ + akun dibuat
  6. GET  superbot /v1/beta/status       -> cek akses beta (redeem invite kalau perlu)
  7. POST superbot /v1/keys              -> API key sbc_
  8. simpan ke farm.txt, verifikasi key, logout, hapus inbox, ulangi

Setup:
  pip install -r requirements.txt

Jalan:
  python superbot.py                 # nanya jumlah akun dulu
  python superbot.py -n 10           # langsung
  python superbot.py -n 1 --debug    # lihat body email mentah

Opsi:
  -n 10            jumlah akun
  --provider tempy|tempyapi|mailtm
  --delay 6        jeda antar akun
  --wait 180       batas detik menunggu email
  --invite KODE    kode invite kalau signup ditutup
  --out farm.txt   file hasil
  --dry-run        cuma cek email+kode
  --debug          cetak body email untuk kalibrasi regex
"""

import argparse
import json
import os
import random
import re
import secrets
import string
import sys
import time
from datetime import datetime, timezone

import requests

SB = "https://superbot.gg"
SB_API = "https://api.superbot.gg/v1"
TEMPY_WEB = "https://tempy.email"
TEMPY_API = "https://api.tempy.email"
MAILTM = "https://api.mail.tm"

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

DEFAULT_COUNT = 10
LOCAL_ALPHABET = string.ascii_lowercase + string.digits

STRONG_CODE = re.compile(r"code\s*(?:is|:)\s*([0-9A-Za-z][0-9A-Za-z-]{5,19})", re.I)
CODE_RE = [
    STRONG_CODE,
    re.compile(r"\b[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){1,3}\b"),
    re.compile(r"\b[0-9A-HJKMNP-TV-Z]{8}\b"),
    re.compile(r"code[=:\s\"']+([0-9A-Za-z-]{6,20})"),
]


class FarmError(Exception):
    pass


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_code(text):
    text = (text or "").strip()
    if not text:
        return None
    for rx in CODE_RE:
        m = rx.search(text)
        if not m:
            continue
        code = (m.group(1) if m.groups() else m.group(0)).upper()
        code = code.strip(" .,:;\"'")
        if 6 <= len(code.replace("-", "")) <= 20:
            return code
    return None


def new_session():
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Origin": SB,
            "Referer": SB + "/invite",
        }
    )
    return s


def ask_count(default=DEFAULT_COUNT):
    while True:
        try:
            raw = input(f"Berapa akun yang mau dibuat? [{default}] ").strip()
        except EOFError:
            return default
        if raw == "":
            return default
        try:
            n = int(raw)
        except ValueError:
            print("  isi angka ya.")
            continue
        if n < 1:
            print("  minimal 1.")
            continue
        if n > 500:
            if input(f"  {n} akun itu banyak, lanjut? (y/n) ").strip().lower() != "y":
                continue
        return n


# ------------------------------------------- tempy lewat endpoint web (no key) ---
class TempyWeb:
    """tempy.email endpoint web. Tanpa akun, tanpa API key, tanpa browser."""

    name = "tempy(web)"

    def __init__(self, debug=False):
        self.debug = debug
        self.s = requests.Session()
        self.s.headers.update(
            {
                "User-Agent": UA,
                "Accept": "application/json, text/plain, */*",
                "Origin": TEMPY_WEB,
                "Referer": TEMPY_WEB + "/",
            }
        )
        try:  # ambil cookie Cloudflare bila ada
            self.s.get(TEMPY_WEB + "/", timeout=30)
        except Exception:
            pass

    def _local(self):
        head = random.choice(string.ascii_lowercase)
        tail = "".join(random.choices(LOCAL_ALPHABET, k=9))
        return "sb" + head + tail

    def create(self):
        for _ in range(4):
            body = {
                "domain": "tempy.email",
                "local_part": self._local(),
                "language": "en",
            }
            r = self.s.post(TEMPY_WEB + "/api/inbox/create", json=body, timeout=30)
            if r.status_code == 409:
                continue
            if r.status_code != 200:
                raise FarmError(f"tempy create {r.status_code}: {r.text[:200]}")
            email = r.json().get("email")
            if not email:
                raise FarmError("tempy create tanpa email")
            self._extend(email)
            return email
        raise FarmError("tempy: semua local_part bentrok")

    def _extend(self, address, minutes=60):
        try:
            self.s.post(
                TEMPY_WEB + "/api/inbox/extend",
                json={"address": address, "minutes": minutes},
                timeout=20,
            )
        except Exception:
            pass

    def wait_code(self, address, timeout=180):
        end = time.time() + timeout
        seen = set()
        while time.time() < end:
            try:
                r = self.s.get(
                    TEMPY_WEB + "/api/inbox/messages",
                    params={"address": address},
                    timeout=25,
                )
            except Exception:
                time.sleep(3)
                continue
            if r.status_code == 404:
                raise FarmError("tempy: inbox sudah tidak ada")
            if r.status_code == 200:
                for m in r.json().get("messages", []):
                    mid = m.get("id")
                    if not mid or mid in seen:
                        continue
                    seen.add(mid)
                    text = (m.get("subject") or "") + "\n" + (m.get("body_text") or "")
                    code = extract_code(text)
                    if not code:
                        try:
                            d = self.s.get(
                                TEMPY_WEB + "/api/inbox/message",
                                params={"address": address, "id": mid},
                                timeout=25,
                            )
                            if d.status_code == 200:
                                j = d.json()
                                text = "\n".join(
                                    str(j.get(k) or "")
                                    for k in ("subject", "body_text", "body_html")
                                )
                                code = extract_code(text)
                        except Exception:
                            pass
                    if self.debug:
                        log(f"  [debug] pesan: {text[:400]!r}")
                    if code:
                        return code, text
            time.sleep(2.5)
        return None, ""

    def drop(self, address):
        try:
            self.s.post(
                TEMPY_WEB + "/api/inbox/delete", json={"address": address}, timeout=20
            )
        except Exception:
            pass

    def close(self):
        pass


# ------------------------------------------------- tempy lewat API (pakai key) ---
class TempyApi:
    name = "tempy(api)"

    def __init__(self, api_key, debug=False):
        if not api_key:
            raise FarmError(
                "TEMPY_KEY kosong (https://tempy.email/developers/auth/start)"
            )
        self.debug = debug
        self.h = {"X-Api-Key": api_key, "content-type": "application/json"}

    def create(self):
        local = "sb" + "".join(random.choices(LOCAL_ALPHABET, k=10))
        r = requests.post(
            f"{TEMPY_API}/v1/mailbox",
            headers=self.h,
            json={"local_part": local},
            timeout=30,
        )
        if r.status_code == 402:
            raise FarmError("tempy: kredit habis (402 no_credits)")
        if r.status_code == 409:
            return self.create()
        if r.status_code != 200:
            raise FarmError(f"tempy create {r.status_code}: {r.text[:200]}")
        return r.json()["email"]

    def wait_code(self, address, timeout=180):
        end = time.time() + timeout
        while time.time() < end:
            left = int(min(30, max(1, end - time.time())))
            r = requests.get(
                f"{TEMPY_API}/v1/mailbox/{address}/messages/wait",
                headers=self.h,
                params={"subject_contains": "sign-in code", "timeout": left},
                timeout=left + 15,
            )
            if r.status_code == 204:
                continue
            if r.status_code != 200:
                raise FarmError(f"tempy wait {r.status_code}: {r.text[:200]}")
            body = r.json().get("body_text") or ""
            code = extract_code(body)
            if code:
                return code, body
        return None, ""

    def drop(self, address):
        try:
            requests.delete(
                f"{TEMPY_API}/v1/mailbox/{address}", headers=self.h, timeout=20
            )
        except Exception:
            pass

    def close(self):
        pass


# ------------------------------------------------------------------ mail.tm ---
class MailTm:
    name = "mailtm"

    def __init__(self, _=None, debug=False):
        self.debug = debug
        r = requests.get(f"{MAILTM}/domains", timeout=30)
        r.raise_for_status()
        items = [d for d in r.json().get("hydra:member", []) if d.get("isActive")]
        if not items:
            raise FarmError("mail.tm: tidak ada domain aktif")
        self.domain = items[0]["domain"]
        self.h = {}

    def create(self):
        user = "sb" + "".join(random.choices(LOCAL_ALPHABET, k=10))
        addr = f"{user}@{self.domain}"
        pw = secrets.token_urlsafe(18)
        r = requests.post(
            f"{MAILTM}/accounts", json={"address": addr, "password": pw}, timeout=30
        )
        if r.status_code not in (200, 201):
            raise FarmError(f"mailtm create {r.status_code}: {r.text[:200]}")
        t = requests.post(
            f"{MAILTM}/token", json={"address": addr, "password": pw}, timeout=30
        )
        if t.status_code != 200:
            raise FarmError(f"mailtm token {t.status_code}: {t.text[:200]}")
        self.h = {"Authorization": "Bearer " + t.json()["token"]}
        return addr

    def wait_code(self, address, timeout=180):
        end = time.time() + timeout
        while time.time() < end:
            r = requests.get(f"{MAILTM}/messages", headers=self.h, timeout=30)
            if r.status_code == 200:
                for m in r.json().get("hydra:member", []):
                    d = requests.get(
                        f"{MAILTM}/messages/{m['id']}", headers=self.h, timeout=30
                    )
                    if d.status_code != 200:
                        continue
                    body = "\n".join(d.json().get("text") or [])
                    code = extract_code(body)
                    if code:
                        return code, body
            time.sleep(4)
        return None, ""

    def drop(self, address):
        try:
            requests.delete(f"{MAILTM}/accounts/{address}", headers=self.h, timeout=20)
        except Exception:
            pass

    def close(self):
        pass


# ------------------------------------------------------------------ superbot ---
def sb_start(sess, email):
    payload = {"email": email, "kind": "cli", "via": "agent"}
    r = sess.post(f"{SB}/auth/email/start", json=payload, timeout=40)
    if r.status_code == 429:
        wait = int(r.headers.get("Retry-After", "30"))
        log(f"  429 saat minta kode, tunggu {wait}s")
        time.sleep(wait + 1)
        r = sess.post(f"{SB}/auth/email/start", json=payload, timeout=40)
    if r.status_code not in (200, 202):
        raise FarmError(f"start {r.status_code}: {r.text[:200]}")


def sb_verify(sess, email, code):
    payload = {
        "email": email,
        "kind": "cli",
        "via": "agent",
        "device_name": "farm-script",
    }
    last = ""
    for variant in dict.fromkeys(
        [code, code.replace("-", ""), code.lower(), code.replace("-", "").lower()]
    ):
        r = sess.post(
            f"{SB}/auth/email/verify", json={**payload, "code": variant}, timeout=40
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code in (400, 401, 410):
            last = r.text[:200]
            continue
        raise FarmError(f"verify {r.status_code}: {r.text[:200]}")
    raise FarmError(f"verify ditolak: {last}")


def sb_beta(sess, token, invite=None):
    h = {"Authorization": "Bearer " + token}
    r = sess.get(f"{SB}/v1/beta/status", headers=h, timeout=30)
    if r.status_code == 200:
        if r.json().get("granted"):
            return True
        if invite:
            d = sess.post(
                f"{SB}/v1/beta/redeem", headers=h, json={"code": invite}, timeout=30
            )
            return d.status_code in (200, 201)
    return False


def sb_mint_key(sess, token, name):
    r = sess.post(
        f"{SB}/v1/keys",
        headers={"Authorization": "Bearer " + token},
        json={"name": name},
        timeout=40,
    )
    if r.status_code != 201:
        raise FarmError(f"mint {r.status_code}: {r.text[:300]}")
    return r.json()["key"]


def key_works(key):
    try:
        r = requests.get(
            f"{SB_API}/models", headers={"Authorization": "Bearer " + key}, timeout=40
        )
        return r.status_code == 200
    except Exception:
        return False


def sb_logout(sess, token):
    for path in ("/auth/logout", "/auth/signout"):
        try:
            r = sess.post(
                SB + path, headers={"Authorization": "Bearer " + token}, timeout=20
            )
            if r.status_code < 400:
                return True
        except Exception:
            pass
    return False


# -------------------------------------------------------------------- main ---
def farm_one(prov, invite, args):
    email = prov.create()
    log(f"inbox: {email}")
    try:
        sess = new_session()
        sb_start(sess, email)
        log("  kode diminta, menunggu email...")
        code, _body = prov.wait_code(email, timeout=args.wait)
        if not code:
            raise FarmError("kode tidak masuk dalam batas waktu")
        log(f"  kode: {code}")
        if args.dry_run:
            return {"email": email, "code": code, "key": None, "ok": True}
        data = sb_verify(sess, email, code)
        token = data.get("access_token")
        if not token:
            raise FarmError(f"tanpa access_token: {json.dumps(data)[:200]}")
        log(
            f"  login ok (created={data.get('created')}, device={data.get('device_id')})"
        )
        if not sb_beta(sess, token, invite):
            log("  ! akses beta belum granted, key mungkin ditolak")
        key = sb_mint_key(sess, token, f"farm-{int(time.time())}")
        ok = key_works(key)
        sb_logout(sess, token)
        log(f"  key: {key[:14]}... valid={ok}")
        return {"email": email, "key": key, "ok": ok}
    finally:
        prov.drop(email)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("-n", "--count", type=int, default=None)
    p.add_argument(
        "--provider", choices=["tempy", "tempyapi", "mailtm"], default="tempy"
    )
    p.add_argument("--delay", type=float, default=6.0)
    p.add_argument("--wait", type=int, default=180)
    p.add_argument("--invite", default=os.getenv("SUPERBOT_INVITE"))
    p.add_argument("--out", default="farm.txt")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    if args.count is None:
        args.count = ask_count()
    if args.count < 1:
        log("jumlah akun minimal 1")
        return

    try:
        if args.provider == "tempy":
            prov = TempyWeb(debug=args.debug)
        elif args.provider == "tempyapi":
            prov = TempyApi(os.getenv("TEMPY_KEY"), debug=args.debug)
        else:
            prov = MailTm(debug=args.debug)
    except FarmError as e:
        log(f"fatal: {e}")
        sys.exit(1)

    log(
        f"provider={prov.name} jumlah={args.count} file={args.out}"
        + (" (dry-run)" if args.dry_run else "")
    )

    done = fail = 0
    try:
        for i in range(1, args.count + 1):
            log(f"--- akun {i}/{args.count} ---")
            try:
                res = farm_one(prov, args.invite, args)
                with open(args.out, "a", encoding="utf-8") as f:
                    f.write(
                        f"{now_iso()} | {res['email']} | {res.get('key') or '-'} | "
                        f"{'ok' if res['ok'] else 'unverified'}\n"
                    )
                done += 1
            except KeyboardInterrupt:
                log("dihentikan user")
                break
            except Exception as e:
                fail += 1
                log(f"  GAGAL: {e}")
                with open("farm_errors.log", "a", encoding="utf-8") as f:
                    f.write(f"{now_iso()} | {e}\n")
            if i < args.count:
                time.sleep(args.delay + random.uniform(0, 2))
    finally:
        prov.close()

    log(f"selesai: {done} sukses, {fail} gagal. hasil di {args.out}")


if __name__ == "__main__":
    try:
        main()
    except FarmError as e:
        log(f"fatal: {e}")
        sys.exit(1)
