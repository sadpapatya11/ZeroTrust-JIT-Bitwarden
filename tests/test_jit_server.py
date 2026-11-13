# -*- coding: utf-8 -*-
"""
jit_server.py testleri. Windows/WSL/Bitwarden gerektirmez:
- bash betiği sahte bir `bw` ile yerel bash'te çalıştırılır,
- HTTP akışı gerçek sunucuda, süreç denetimi ve kasa çağrıları taklit edilerek test edilir.

Çalıştırma (proje kökünden):  python -m unittest discover -s tests -v
"""
import base64
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import jit_server  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# --------------------------------------------------------------------------- #
class ApprovalManagerTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.m = jit_server.ApprovalManager(validity_seconds=30, result_ttl_seconds=30, clock=self.clock)

    def test_create_returns_distinct_secrets(self):
        c = self.m.create("demo", "python.exe")
        self.assertNotEqual(c["otp"], c["request_id"])
        self.assertGreaterEqual(len(c["otp"]), 16)

    def test_only_one_active_request(self):
        self.assertIsNotNone(self.m.create("a", "p"))
        self.assertIsNone(self.m.create("b", "p"))

    def test_slot_frees_after_expiry(self):
        self.m.create("a", "p")
        self.clock.t += 31
        self.assertIsNotNone(self.m.create("b", "p"))

    def test_wrong_otp_burns_request(self):
        c = self.m.create("a", "p")
        ok, _, _ = self.m.approve("yanlis")
        self.assertFalse(ok)
        ok2, _, _ = self.m.approve(c["otp"])  # doğru kod bile artık geçersiz
        self.assertFalse(ok2)
        self.assertEqual(self.m.fetch(c["request_id"])[0], "gone")

    def test_non_ascii_token_does_not_crash(self):
        self.m.create("a", "p")
        ok, _, _ = self.m.approve("şğıüö")
        self.assertFalse(ok)

    def test_approve_is_single_use(self):
        c = self.m.create("a", "p")
        ok, _, ctx = self.m.approve(c["otp"])
        self.assertTrue(ok)
        self.assertEqual(ctx["item"], "a")
        self.assertFalse(self.m.approve(c["otp"])[0])

    def test_expired_otp_rejected(self):
        c = self.m.create("a", "p")
        self.clock.t += 31
        self.assertFalse(self.m.approve(c["otp"])[0])

    def test_fetch_lifecycle_is_one_shot(self):
        c = self.m.create("a", "p")
        rid = c["request_id"]
        self.assertEqual(self.m.fetch(rid)[0], "waiting")
        self.m.approve(c["otp"])
        self.assertEqual(self.m.fetch(rid)[0], "waiting")  # processing
        self.m.complete(rid, value="S3CRET")
        self.assertEqual(self.m.fetch(rid), ("ready", "S3CRET"))
        self.assertEqual(self.m.fetch(rid)[0], "gone")

    def test_result_expires(self):
        c = self.m.create("a", "p")
        self.m.approve(c["otp"])
        self.m.complete(c["request_id"], value="S3CRET")
        self.clock.t += 31
        self.assertEqual(self.m.fetch(c["request_id"])[0], "gone")

    def test_failed_result_reported_once(self):
        c = self.m.create("a", "p")
        self.m.approve(c["otp"])
        self.m.complete(c["request_id"], error="hata")
        self.assertEqual(self.m.fetch(c["request_id"]), ("failed", "hata"))
        self.assertEqual(self.m.fetch(c["request_id"])[0], "gone")

    def test_unknown_request_id(self):
        self.assertEqual(self.m.fetch("yok")[0], "gone")

    def test_pending_info_has_no_otp(self):
        c = self.m.create("a", "python.exe", "not")
        info = self.m.pending_info()
        self.assertEqual(info["item"], "a")
        self.assertNotIn(c["otp"], json.dumps(info))


# --------------------------------------------------------------------------- #
class HelperTests(unittest.TestCase):
    def test_load_allowed_items(self):
        items = jit_server.load_allowed_items("OpenAI Key, Hetzner:notes ,abc-uuid,, ")
        self.assertEqual(items["OpenAI Key"], ("OpenAI Key", "password"))
        self.assertEqual(items["Hetzner:notes"], ("Hetzner", "notes"))
        self.assertEqual(items["abc-uuid"], ("abc-uuid", "password"))
        self.assertEqual(len(items), 3)

    def test_load_allowed_items_unknown_field_is_part_of_name(self):
        self.assertEqual(jit_server.load_allowed_items("x:foo")["x:foo"], ("x:foo", "password"))

    def test_empty_allowlist(self):
        self.assertEqual(jit_server.load_allowed_items(""), {})

    def test_sanitize_note(self):
        self.assertEqual(jit_server.sanitize_note("a\nb\x00c"), "a b c")
        self.assertEqual(len(jit_server.sanitize_note("x" * 500)), jit_server.MAX_NOTE_LENGTH)

    def test_strip_query_hides_secrets(self):
        out = jit_server.strip_query("GET /approve?token=ABC123&x=1 HTTP/1.1")
        self.assertNotIn("ABC123", out)
        self.assertIn("/approve", out)


class CallerInspectionTests(unittest.TestCase):
    def test_remote_non_tailscale_denied(self):
        self.assertFalse(jit_server.inspect_caller_process("192.168.1.50", 5000, "/approve")[0])
        self.assertFalse(jit_server.inspect_caller_process("8.8.8.8", 5000, "/approve")[0])

    def test_tailscale_range_boundaries(self):
        self.assertTrue(jit_server.is_tailscale_ip("100.64.0.1"))
        self.assertTrue(jit_server.is_tailscale_ip("100.127.255.254"))
        self.assertFalse(jit_server.is_tailscale_ip("100.128.0.1"))
        self.assertFalse(jit_server.is_tailscale_ip("100.63.255.255"))
        self.assertFalse(jit_server.is_tailscale_ip("not-an-ip"))

    def test_tailscale_only_approve(self):
        self.assertTrue(jit_server.inspect_caller_process("100.101.102.103", 5000, "/approve")[0])
        for path in ("/fetch", "/request_approval", "/lock", "/status", ""):
            self.assertFalse(jit_server.inspect_caller_process("100.101.102.103", 5000, path)[0], path)

    def test_loopback_without_psutil_is_denied(self):
        with mock.patch.object(jit_server, "psutil", None):
            self.assertFalse(jit_server.inspect_caller_process("127.0.0.1", 5000, "/status")[0])

    def test_loopback_unknown_port_denied(self):
        self.assertFalse(jit_server.inspect_caller_process("127.0.0.1", 1, "/status")[0])

    def test_loopback_allowed_and_denied_process_names(self):
        class Addr:
            def __init__(self, port):
                self.port = port

        class Conn:
            def __init__(self, pid):
                self.laddr, self.raddr, self.pid = Addr(40000), Addr(jit_server.PORT), pid

        fake = mock.MagicMock()
        fake.net_connections.return_value = [Conn(11)]
        for name, expected in (("Python.EXE", True), ("chrome.exe", False)):
            fake.Process.return_value.name.return_value = name
            with mock.patch.object(jit_server, "psutil", fake):
                self.assertEqual(jit_server.inspect_caller_process("127.0.0.1", 40000, "/status")[0], expected)

    def test_ipv4_mapped_loopback(self):
        self.assertTrue(jit_server.is_loopback("::ffff:127.0.0.1"))


# --------------------------------------------------------------------------- #
FAKE_BW = r'''#!/usr/bin/env bash
echo "$@" >> "$FAKE_BW_DIR/calls.log"
case "$1" in
  unlock)
    if [ "$BW_PASSWORD" = "$FAKE_BW_EXPECTED_PW" ]; then printf 'SESSION1234567890'; else exit 1; fi ;;
  get)
    if [ "$5" != "SESSION1234567890" ]; then exit 1; fi
    if [ "$3" = "missing" ]; then exit 1; fi
    printf '%s\n' "$FAKE_BW_SECRET" ;;
  lock) touch "$FAKE_BW_DIR/locked" ;;
esac
'''


@unittest.skipUnless(shutil.which("bash") and shutil.which("base64"), "bash/base64 gerekli")
class BashScriptTests(unittest.TestCase):
    """BW_FETCH_SCRIPT'i sahte bw ile gerçek bash'te çalıştırır."""

    PASSWORD = "şifre-ğüı-123"
    SECRET = "sk-test-ççş-değer"

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        bw = os.path.join(self.dir, "bw")
        with open(bw, "w", encoding="utf-8") as f:
            f.write(FAKE_BW)
        os.chmod(bw, os.stat(bw).st_mode | stat.S_IXUSR)
        env = {
            "JIT_BW_BIN": bw, "FAKE_BW_DIR": self.dir,
            "FAKE_BW_EXPECTED_PW": self.PASSWORD, "FAKE_BW_SECRET": self.SECRET,
        }
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(jit_server, "WSL_PREFIX", [])
        p2.start()
        self.addCleanup(p2.stop)

    def run_fetch(self, item="demo", field="password", password=None):
        pw = self.PASSWORD if password is None else password
        b64 = base64.b64encode(pw.encode("utf-8")).decode("ascii")
        return jit_server.run_wsl_script(
            jit_server.BW_FETCH_SCRIPT,
            {"JIT_PW_B64": b64, "JIT_BW_ITEM": item, "JIT_BW_FIELD": field},
        )

    def locked(self):
        return os.path.exists(os.path.join(self.dir, "locked"))

    def test_success_returns_secret_and_locks(self):
        res = self.run_fetch()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.rstrip("\n"), self.SECRET)  # Türkçe karakterler bozulmadı
        self.assertTrue(self.locked(), "trap kasayı kilitlemeliydi")

    def test_wrong_password_exit_11_and_still_locks(self):
        res = self.run_fetch(password="yanlis")
        self.assertEqual(res.returncode, 11)
        self.assertEqual(res.stdout, "")
        self.assertTrue(self.locked())

    def test_missing_item_exit_13_and_still_locks(self):
        res = self.run_fetch(item="missing")
        self.assertEqual(res.returncode, 13)
        self.assertTrue(self.locked())

    def test_password_never_in_command_arguments(self):
        self.run_fetch()
        with open(os.path.join(self.dir, "calls.log"), encoding="utf-8") as f:
            calls = f.read()
        self.assertNotIn(self.PASSWORD, calls)
        self.assertNotIn(base64.b64encode(self.PASSWORD.encode()).decode(), calls)
        self.assertIn("--passwordenv BW_PASSWORD", calls)

    def test_execute_bw_lock_uses_script(self):
        self.assertTrue(jit_server.execute_bw_lock())
        self.assertTrue(self.locked())


# --------------------------------------------------------------------------- #
class HTTPFlowTests(unittest.TestCase):
    """Gerçek HTTP sunucusu; süreç denetimi, webhook ve kasa taklit edilir."""

    def setUp(self):
        self.otps = []
        self.webhook_ok = True
        self.vault_result = (True, "S3CRET")

        def fake_send(otp, item, caller, note):
            if self.webhook_ok:
                self.otps.append(otp)
            return self.webhook_ok

        patches = [
            mock.patch.dict(os.environ, {"JIT_ALLOWED_ITEMS": "demo"}),
            mock.patch.object(jit_server, "inspect_caller_process", return_value=(True, "test", "python.exe")),
            mock.patch.object(jit_server, "send_mobile_approval", side_effect=fake_send),
            mock.patch.object(jit_server, "fetch_secret_from_vault", side_effect=lambda i, f: self.vault_result),
            mock.patch.object(jit_server, "approvals", jit_server.ApprovalManager()),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.server = jit_server.make_servers(["127.0.0.1"], 0)[0]
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
                return r.status, r.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8")

    def request(self, item="demo"):
        code, body = self.get(f"/request_approval?item={item}")
        return code, (json.loads(body) if code == 200 else body)

    def test_full_happy_path(self):
        code, resp = self.request()
        self.assertEqual(code, 200)
        rid = resp["request_id"]
        self.assertNotIn(self.otps[0], json.dumps(resp), "OTP ajana dönmemeli")
        self.assertEqual(self.get(f"/fetch?id={rid}")[0], 202)
        self.assertEqual(self.get(f"/approve?token={self.otps[0]}")[0], 200)
        self.assertEqual(self.get(f"/fetch?id={rid}"), (200, "S3CRET"))
        self.assertEqual(self.get(f"/fetch?id={rid}")[0], 404)  # tek sefer

    def test_item_not_on_allowlist(self):
        self.assertEqual(self.request("baska")[0], 403)
        self.assertEqual(self.otps, [])

    def test_empty_allowlist_refuses_everything(self):
        with mock.patch.dict(os.environ, {"JIT_ALLOWED_ITEMS": ""}):
            self.assertEqual(self.request()[0], 503)

    def test_second_request_while_pending_is_429(self):
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.request()[0], 429)

    def test_wrong_token_burns_request(self):
        _, resp = self.request()
        self.assertEqual(self.get("/approve?token=yanlis")[0], 403)
        self.assertEqual(self.get(f"/approve?token={self.otps[0]}")[0], 403)
        self.assertEqual(self.get(f"/fetch?id={resp['request_id']}")[0], 404)

    def test_webhook_failure_frees_slot(self):
        self.webhook_ok = False
        self.assertEqual(self.request()[0], 502)
        self.webhook_ok = True
        self.assertEqual(self.request()[0], 200)

    def test_vault_failure_is_reported_not_leaked(self):
        self.vault_result = (False, "Bitwarden kilidi açılamadı")
        _, resp = self.request()
        self.assertEqual(self.get(f"/approve?token={self.otps[0]}")[0], 500)
        code, body = self.get(f"/fetch?id={resp['request_id']}")
        self.assertEqual(code, 502)
        self.assertIn("açılamadı", body)

    def test_fetch_without_valid_id(self):
        self.assertEqual(self.get("/fetch?id=")[0], 404)
        self.assertEqual(self.get("/fetch")[0], 404)

    def test_status_never_contains_otp(self):
        self.request()
        code, body = self.get("/status")
        self.assertEqual(code, 200)
        self.assertNotIn(self.otps[0], body)
        self.assertEqual(json.loads(body)["pending"]["item"], "demo")

    def test_denied_caller_gets_403(self):
        with mock.patch.object(jit_server, "inspect_caller_process", return_value=(False, "yasak", "")):
            self.assertEqual(self.get("/status")[0], 403)

    def test_unknown_route(self):
        self.assertEqual(self.get("/nope")[0], 404)


if __name__ == "__main__":
    unittest.main()
