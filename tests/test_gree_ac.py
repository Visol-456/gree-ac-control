#!/usr/bin/env python3
"""Unit tests for gree_ac.py — UDP I/O is mocked; crypto and parsing are real.

Run: python3 -m unittest discover -s tests
Requires: pycryptodome
"""
import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import gree_ac

GENERIC = gree_ac.GENERIC_KEY
DEV_KEY = b"testdevkey123456"  # must be exactly 16 bytes for AES-128

MAC = "aabbccddeeff"


def pack_response(inner: dict, key: bytes) -> dict:
    """Build the outer JSON a device would return for a given inner pack."""
    return {"t": "pack", "i": 1, "uid": 0, "cid": "", "tcid": "",
            "pack": gree_ac.enc_ecb(inner, key)}


class TestCrypto(unittest.TestCase):
    def test_ecb_roundtrip(self):
        inner = {"t": "dev", "mac": MAC, "mid": "11002"}
        b64 = gree_ac.enc_ecb(inner, GENERIC)
        self.assertEqual(gree_ac.dec_ecb(b64, GENERIC), inner)

    def test_ecb_pkcs7_padding_removed(self):
        # 1-byte payload gets 15 bytes of padding; roundtrip must drop it all
        inner = {"t": "x"}
        b64 = gree_ac.enc_ecb(inner, GENERIC)
        self.assertEqual(gree_ac.dec_ecb(b64, GENERIC), inner)

    def test_gcm_roundtrip(self):
        inner = {"t": "dev", "mac": MAC}
        enc = gree_ac.enc_gcm(inner, gree_ac.GENERIC_GCM_KEY)
        self.assertIn("tag", enc)
        self.assertEqual(gree_ac.dec_gcm(enc["pack"], enc["tag"], gree_ac.GENERIC_GCM_KEY), inner)

    def test_gcm_tamper_detected(self):
        inner = {"t": "dev", "mac": MAC}
        enc = gree_ac.enc_gcm(inner, gree_ac.GENERIC_GCM_KEY)
        tampered = enc["pack"][:-4] + ("AAAA" if not enc["pack"].endswith("AAAA") else "BBBB")
        with self.assertRaises(Exception):
            gree_ac.dec_gcm(tampered, enc["tag"], gree_ac.GENERIC_GCM_KEY)

    def test_decrypt_pack_auto_detect_gcm(self):
        inner = {"t": "dev", "mac": MAC}
        # GCM response has a tag -> decrypt_pack must pick GCM
        enc = gree_ac.enc_gcm(inner, gree_ac.GENERIC_GCM_KEY)
        resp = {"t": "pack", "pack": enc["pack"], "tag": enc["tag"]}
        self.assertEqual(gree_ac.decrypt_pack(resp, gree_ac.GENERIC_GCM_KEY), inner)
        # ECB response has no tag -> ECB path
        resp2 = pack_response(inner, GENERIC)
        self.assertEqual(gree_ac.decrypt_pack(resp2, GENERIC), inner)

    def test_bad_base64_raises(self):
        with self.assertRaises(Exception):
            gree_ac.dec_ecb("not-base64!!!", GENERIC)


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")

    def tearDown(self):
        gree_ac.CONFIG_PATH = self.orig_path

    def test_save_and_load(self):
        gree_ac.save_device("192.168.1.10", MAC, "abc123")
        devs = gree_ac.load_devices()
        self.assertEqual(devs["192.168.1.10"], {"mac": MAC, "key": "abc123"})

    def test_load_missing_file_returns_empty(self):
        self.assertEqual(gree_ac.load_devices(), {})

    def test_save_merges_not_overwrites(self):
        gree_ac.save_device("192.168.1.10", MAC, "abc123")
        gree_ac.save_device("192.168.1.11", "112233445566", "xyz789")
        devs = gree_ac.load_devices()
        self.assertEqual(set(devs), {"192.168.1.10", "192.168.1.11"})

    def test_load_corrupt_file_returns_empty(self):
        with open(gree_ac.CONFIG_PATH, "w") as f:
            f.write("{not json!!")
        self.assertEqual(gree_ac.load_devices(), {})


class TestList(unittest.TestCase):
    @mock.patch.object(gree_ac.socket, "socket")
    def test_list_finds_devices_and_skips_junk(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        good = pack_response({"t": "dev", "mac": MAC, "bc": "ABC__", "mid": "11002"}, GENERIC)
        junk = b"garbage not json"
        sock.recvfrom.side_effect = [(json.dumps(good).encode(), ("192.168.1.10", 7000)),
                                     (junk, ("192.168.1.11", 7000)),
                                     socket.timeout]
        args = mock.Mock(sweep=None)
        self.assertEqual(gree_ac.cmd_list(args), 0)
        outputs = [c[0][0] for c in sock.sendto.call_args_list]
        self.assertTrue(any(b'{"t":"scan"}' in o for o in outputs))

    @mock.patch.object(gree_ac.socket, "socket")
    def test_list_no_devices_hints(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        sock.recvfrom.side_effect = socket.timeout
        args = mock.Mock(sweep=None)
        self.assertEqual(gree_ac.cmd_list(args), 0)


class TestBind(unittest.TestCase):
    @mock.patch.object(gree_ac.socket, "socket")
    def test_bind_no_save_prints_key(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        scan_resp = pack_response({"t": "dev", "mac": MAC, "bc": "ABC__", "mid": "11002"}, GENERIC)
        bind_resp = pack_response({"t": "bindok", "mac": MAC, "key": "devkey123", "r": 200}, GENERIC)
        sock.recvfrom.side_effect = [(json.dumps(scan_resp).encode(), ("192.168.1.10", 7000)),
                                     (json.dumps(bind_resp).encode(), ("192.168.1.10", 7000))]
        args = mock.Mock(ip="192.168.1.10", no_save=True)
        self.assertEqual(gree_ac.cmd_bind(args), 0)

    @mock.patch.object(gree_ac.socket, "socket")
    def test_bind_timeout_reports_cleanly(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        sock.recvfrom.side_effect = socket.timeout
        args = mock.Mock(ip="192.168.1.10", no_save=False)
        self.assertEqual(gree_ac.cmd_bind(args), 1)


class TestWindowsRobustness(unittest.TestCase):
    """Windows UDP quirks: ConnectionResetError (WSAECONNRESET 10054) must not crash."""

    @mock.patch.object(gree_ac.socket, "socket")
    def test_send_recv_sendto_error_returns_none(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        sock.sendto.side_effect = OSError("send failed")
        self.assertIsNone(gree_ac.send_recv(b"ping", "192.168.1.99"))

    @mock.patch.object(gree_ac.socket, "socket")
    def test_send_recv_connection_reset_returns_none(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        sock.recvfrom.side_effect = ConnectionResetError(10054, "An existing connection was forcibly closed")
        self.assertIsNone(gree_ac.send_recv(b"ping", "192.168.1.99"))

    @mock.patch.object(gree_ac.socket, "socket")
    def test_list_sendto_failure_reports_cleanly(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        sock.sendto.side_effect = OSError("send failed")
        args = mock.Mock(sweep=None)
        self.assertEqual(gree_ac.cmd_list(args), 1)

    @mock.patch.object(gree_ac.socket, "socket")
    def test_list_connection_reset_keeps_listening(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        good = pack_response({"t": "dev", "mac": MAC, "bc": "ABC__", "mid": "11002"}, GENERIC)
        # first recvfrom raises ConnectionResetError (sweep hit a dead host),
        # second returns a real device, then timeout ends the loop
        sock.recvfrom.side_effect = [
            ConnectionResetError(10054, "reset"),
            (json.dumps(good).encode(), ("192.168.1.10", 7000)),
            socket.timeout,
        ]
        args = mock.Mock(sweep="192.168.1.0/30")
        self.assertEqual(gree_ac.cmd_list(args), 0)

    @mock.patch.object(gree_ac.socket, "socket")
    def test_bind_connection_reset_reports_cleanly(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        sock.recvfrom.side_effect = ConnectionResetError(10054, "reset")
        args = mock.Mock(ip="192.168.1.10", no_save=False)
        self.assertEqual(gree_ac.cmd_bind(args), 1)


class TestStatus(unittest.TestCase):
    @mock.patch.object(gree_ac.socket, "socket")
    def test_status_missing_fields_do_not_crash(self, mock_socket):
        # device returns only Pow — no TemUn/SetTem/WdSpd; must not KeyError
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        status_resp = pack_response({"t": "dat", "mac": MAC, "cols": ["Pow"], "dat": [1], "r": 200}, DEV_KEY)
        sock.recvfrom.return_value = (json.dumps(status_resp).encode(), ("192.168.1.10", 7000))
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            args = mock.Mock(ip="192.168.1.10")
            self.assertEqual(gree_ac.cmd_status(args), 0)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path

    @mock.patch.object(gree_ac.socket, "socket")
    def test_status_garbage_response_cleanly_skips(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        # first recvfrom (status request) returns garbage JSON that fails to parse
        sock.recvfrom.side_effect = [(b"this is not json at all", ("192.168.1.10", 7000))]
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            args = mock.Mock(ip="192.168.1.10")
            self.assertEqual(gree_ac.cmd_status(args), 0)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path

    @mock.patch.object(gree_ac.socket, "socket")
    def test_status_decrypt_failure_prints_once(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        # valid outer JSON but an undecryptable pack -> decrypt failure
        sock.recvfrom.return_value = (
            json.dumps({"t": "pack", "pack": "not-base64!!!"}).encode(),
            ("192.168.1.10", 7000),
        )
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            args = mock.Mock(ip="192.168.1.10")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = gree_ac.cmd_status(args)
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("status decrypt failed", out)
            self.assertNotIn("no response", out)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path


class TestSet(unittest.TestCase):
    def test_unknown_field_rejected(self):
        args = mock.Mock(ip="192.168.1.10", kv=["Bogus=1"])
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            self.assertEqual(gree_ac.cmd_set(args), 1)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path

    def test_non_integer_rejected(self):
        args = mock.Mock(ip="192.168.1.10", kv=["SetTem=26.5"])
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            self.assertEqual(gree_ac.cmd_set(args), 1)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path

    @mock.patch.object(gree_ac.socket, "socket")
    def test_set_success(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        set_resp = pack_response({"t": "res", "mac": MAC, "opt": ["Pow"], "p": [1], "val": [1], "r": 200}, DEV_KEY)
        sock.recvfrom.return_value = (json.dumps(set_resp).encode(), ("192.168.1.10", 7000))
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            args = mock.Mock(ip="192.168.1.10", kv=["Pow=1"])
            self.assertEqual(gree_ac.cmd_set(args), 0)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path

    @mock.patch.object(gree_ac.socket, "socket")
    def test_set_r_not_200_reports_error(self, mock_socket):
        sock = mock.MagicMock()
        mock_socket.return_value = sock
        set_resp = pack_response({"t": "res", "mac": MAC, "opt": ["Pow"], "p": [1], "r": 400}, DEV_KEY)
        sock.recvfrom.return_value = (json.dumps(set_resp).encode(), ("192.168.1.10", 7000))
        self.tmp = tempfile.mkdtemp()
        self.orig_path = gree_ac.CONFIG_PATH
        gree_ac.CONFIG_PATH = os.path.join(self.tmp, "devices.json")
        try:
            gree_ac.save_device("192.168.1.10", MAC, DEV_KEY.decode())
            args = mock.Mock(ip="192.168.1.10", kv=["Pow=1"])
            self.assertEqual(gree_ac.cmd_set(args), 1)
        finally:
            gree_ac.CONFIG_PATH = self.orig_path


if __name__ == "__main__":
    unittest.main()
