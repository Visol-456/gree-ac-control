#!/usr/bin/env python3
"""Gree AC LAN control CLI — UDP 7000, AES128-ECB/GCM pack protocol.

Usage:
  gree_ac.py list [--sweep CIDR]        # scan LAN for devices (broadcast + optional unicast sweep)
  gree_ac.py bind <ip> [--no-save]      # scan a single IP -> bind -> save key to config
  gree_ac.py add <ip> <mac> <key>       # manually add a device to config
  gree_ac.py status [ip]                # read status (all devices if no ip)
  gree_ac.py set <ip> k=v ...           # control, e.g. Pow=1 Mod=1 SetTem=24 WdSpd=1
"""
import argparse
import base64
import json
import os
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

GENERIC_KEY = b"a3K8Bx%2r8Y7#xDh"  # public reverse-engineered key, same for all units
GENERIC_GCM_KEY = b"{yxAHAY_Lm6pbC/<"
GCM_IV = b"\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13"
GCM_ADD = b"qualcomm-test"
PORT = 7000
TIMEOUT = 4

# Config lives OUTSIDE the script so the install dir can be read-only
# and keys never end up in git. Override with $GREE_DEVICES if you like.
CONFIG_PATH = os.environ.get("GREE_DEVICES", os.path.expanduser("~/.config/gree-ac-control/devices.json"))

STATUS_COLS = ["Pow", "Mod", "SetTem", "WdSpd", "Air", "Blo", "Health", "SwhSlp",
               "Lig", "SwingLfRig", "SwUpDn", "Quiet", "Tur", "StHt", "TemUn",
               "HeatCoolType", "TemRec", "SvSt"]

# Known settable fields (int values). Anything else is rejected up front.
NUMERIC_FIELDS = {"Pow", "Mod", "SetTem", "WdSpd", "Air", "Blo", "Health", "SwhSlp",
                  "Lig", "SwingLfRig", "SwUpDn", "Quiet", "Tur", "StHt", "TemUn",
                  "HeatCoolType", "TemRec", "SvSt"}

MODES = {0: "auto", 1: "cool", 2: "dry", 3: "fan", 4: "heat"}
FAN = {0: "auto", 1: "low", 2: "med-lo", 3: "med", 4: "med-hi", 5: "high"}


# ---------- config ----------

def load_devices() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_device(ip: str, mac: str, key: str):
    devices = load_devices()
    devices[ip] = {"mac": mac, "key": key}
    cfg_dir = os.path.dirname(CONFIG_PATH)
    if cfg_dir:  # GREE_DEVICES may point at a bare filename (cwd-relative)
        os.makedirs(cfg_dir, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(devices, f, indent=2)
    try:  # keys are sensitive; lock the file to the current user
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


# ---------- crypto (ECB + GCM) ----------

def enc_ecb(payload: dict, key: bytes) -> str:
    c = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(c.encrypt(pad(json.dumps(payload).encode(), AES.block_size))).decode()


def dec_ecb(b64: str, key: bytes) -> dict:
    c = AES.new(key, AES.MODE_ECB)
    return json.loads(unpad(c.decrypt(base64.b64decode(b64)), AES.block_size).decode())


def enc_gcm(payload: dict, key: bytes) -> dict:
    c = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
    c.update(GCM_ADD)
    ct, tag = c.encrypt_and_digest(json.dumps(payload).encode())
    return {"pack": base64.b64encode(ct).decode(), "tag": base64.b64encode(tag).decode()}


def dec_gcm(pack_b64: str, tag_b64: str, key: bytes) -> dict:
    c = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
    c.update(GCM_ADD)
    plain = c.decrypt_and_verify(base64.b64decode(pack_b64), base64.b64decode(tag_b64))
    return json.loads(plain.replace(b"\xff", b"").decode())


def decrypt_pack(resp: dict, key: bytes) -> dict:
    """Decrypt a pack response, auto-detecting ECB vs GCM by the presence of `tag`."""
    if "tag" in resp:
        return dec_gcm(resp["pack"], resp["tag"], key)
    return dec_ecb(resp["pack"], key)


def encrypt_pack(payload: dict, key: bytes, use_gcm: bool) -> dict:
    if use_gcm:
        return enc_gcm(payload, key)
    return {"pack": enc_ecb(payload, key)}


# ---------- network ----------

def send_recv(payload: bytes, ip: str, timeout: float = TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, PORT))
        data, _ = s.recvfrom(4096)
        return json.loads(data[0:data.rfind(b"}") + 1])
    except (socket.timeout, OSError, ValueError, json.JSONDecodeError):
        # OSError covers sendto/recvfrom failures: on Windows, ICMP port
        # unreachable surfaces as 10054 on recvfrom. Treat as no response.
        return None
    finally:
        s.close()


def pack_req(tcid: str, inner: dict, key: bytes, use_gcm: bool = False, i: int = 0) -> dict:
    packed = encrypt_pack(inner, key, use_gcm)
    req = {"cid": "app", "i": i, "t": "pack", "uid": 0, "tcid": tcid}
    req.update(packed)
    return req


# ---------- commands ----------

def cmd_list(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    targets = [("255.255.255.255", PORT)]
    if args.sweep:
        import ipaddress
        try:
            net = ipaddress.ip_network(args.sweep, strict=False)
            if net.num_addresses > 1024:
                print(f"error: {args.sweep} too large (use /22 or smaller)")
                return 1
            targets += [(str(h), PORT) for h in net.hosts()]
        except ValueError as e:
            print(f"error: bad CIDR {args.sweep}: {e}")
            return 1
    sent = 0
    for ip, port in targets:
        try:
            s.sendto(b'{"t":"scan"}', (ip, port))
            sent += 1
        except OSError:
            continue
    if sent == 0:
        print("error: could not send scan packets (check network/firewall)")
        s.close()
        return 1
    found = []
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except socket.timeout:
            break
        except OSError:
            # ConnectionResetError etc. (Windows 10054 on unroutable unicast):
            # keep listening for other replies instead of crashing.
            continue
        try:
            resp = json.loads(data[0:data.rfind(b"}") + 1])
            dev = decrypt_pack(resp, GENERIC_GCM_KEY if "tag" in resp else GENERIC_KEY)
            found.append((addr[0], dev))
            print(f"{addr[0]}: mac={dev.get('mac')} bc={dev.get('bc')} mid={dev.get('mid')}")
        except Exception as e:
            print(f"{addr[0]}: skipped bad packet ({e})")
    s.close()
    if not found:
        print("no devices found")
        print("check: same WiFi network? firewall allowing UDP 7000? AP isolation on?")
        if not args.sweep:
            print("hint: retry with --sweep 192.168.x.0/24 (some routers block broadcast)")
    else:
        print(f"\nfound {len(found)} device(s); bind one with: gree_ac.py bind <ip>")
    return 0


def bind_device(ip: str, mac: str, use_gcm: bool = False) -> str:
    """Bind to a device, return its unique key."""
    bind_pack = {"mac": mac, "t": "bind", "uid": 0}
    req = pack_req(mac, bind_pack, GENERIC_GCM_KEY if use_gcm else GENERIC_KEY, use_gcm=use_gcm, i=1)
    resp = send_recv(json.dumps(req).encode(), ip)
    if not resp:
        return None
    try:
        bind_resp = decrypt_pack(resp, GENERIC_GCM_KEY if "tag" in resp else GENERIC_KEY)
    except Exception:
        # malformed bind reply (missing pack/tag, bad padding, wrong key) -> treat as failed
        return None
    if bind_resp.get("t") == "bindok":
        return bind_resp.get("key")
    return None


def cmd_bind(args):
    ip = args.ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(b'{"t":"scan"}', (ip, PORT))
        data, _ = s.recvfrom(4096)
    except (socket.timeout, OSError):
        # OSError covers sendto/recvfrom failures (Windows 10054 on closed ports)
        print(f"{ip}: no response (same WiFi network required; check firewall UDP 7000 / AP isolation)")
        return 1
    finally:
        s.close()
    try:
        resp = json.loads(data[0:data.rfind(b"}") + 1])
        dev = decrypt_pack(resp, GENERIC_GCM_KEY if "tag" in resp else GENERIC_KEY)
    except Exception as e:
        print(f"{ip}: bad scan response ({e})")
        return 1
    mac = dev.get("mac")
    print(f"{ip}: mac={mac} bc={dev.get('bc')} mid={dev.get('mid')}")
    key = bind_device(ip, mac, use_gcm="tag" in resp)
    if not key:
        print("bind failed (GCM devices are supported; if this keeps failing, the module may need a factory reset)")
        return 1
    if args.no_save:
        # only print the key when the user opted out of saving it to disk
        print(f"bind ok, key={key}")
        print("note: key printed in plaintext — it may be in your terminal scrollback/shell history")
        print(f"\nadd to config manually:")
        print(f'  gree_ac.py add {ip} {mac} {key}')
    else:
        save_device(ip, mac, key)
        print(f"bind ok, saved to {CONFIG_PATH} (chmod 600)")
    return 0


def cmd_add(args):
    save_device(args.ip, args.mac, args.key)
    print(f"saved {args.ip} -> {CONFIG_PATH}")
    print("note: key was passed on the command line — it may be in your shell history")
    return 0


def get_status(ip: str, mac: str, key: str) -> dict:
    req = pack_req(mac, {"cols": STATUS_COLS, "mac": mac, "t": "status"}, key.encode())
    resp = send_recv(json.dumps(req).encode(), ip)
    if not resp:
        return None
    try:
        return decrypt_pack(resp, key.encode())
    except Exception as e:
        raise ValueError(f"status decrypt failed ({e})") from e


def cmd_status(args):
    devices = load_devices()
    if args.ip and args.ip not in devices:
        print(f"unknown device {args.ip}; run `list` then `bind <ip>`, or `add <ip> <mac> <key>`")
        return 1
    if not args.ip and not devices:
        print("no devices configured; run `list` to discover, then `bind <ip>`")
        return 0
    ips = [args.ip] if args.ip else list(devices)
    for ip in ips:
        d = devices[ip]
        try:
            st = get_status(ip, d["mac"], d["key"])
        except ValueError as e:
            print(f"{ip}: {e}")
            continue
        if not st:
            print(f"{ip}: no response")
            continue
        dat = dict(zip(st.get("cols", []), st.get("dat", [])))
        print(f"\n{ip}")
        pow_state = "ON" if dat.get("Pow") == 1 else ("OFF" if dat.get("Pow") == 0 else "?")
        print(f"  Pow={dat.get('Pow', '?')} ({pow_state})")
        print(f"  Mod={dat.get('Mod', '?')} ({MODES.get(dat.get('Mod'), '?')})")
        tem = dat.get('SetTem')
        if tem is None:
            print("  SetTem=?")
        else:
            print(f"  SetTem={tem}{'F' if dat.get('TemUn') else 'C'}")
        print(f"  WdSpd={dat.get('WdSpd', '?')} ({FAN.get(dat.get('WdSpd'), '?')})")
        for k in ["Tur", "Quiet", "Health", "SwhSlp", "Lig", "Blo", "SvSt"]:
            if k in dat:
                print(f"  {k}={dat[k]}")
    return 0


def cmd_set(args):
    devices = load_devices()
    ip = args.ip
    if ip not in devices:
        print(f"unknown device {ip}; run `list` then `bind <ip>`, or `add <ip> <mac> <key>`")
        return 1
    d = devices[ip]
    kv = {}
    for item in args.kv:
        k, _, v = item.partition("=")
        if not k or k not in NUMERIC_FIELDS:
            print(f"error: unknown field '{k}' (known: {', '.join(sorted(NUMERIC_FIELDS))})")
            return 1
        try:
            kv[k] = int(v)
        except ValueError:
            print(f"error: '{v}' is not a valid integer for {k}")
            return 1
    print(f"set {ip}: {kv}")
    req = pack_req(d["mac"], {"opt": list(kv.keys()), "p": list(kv.values()), "t": "cmd"}, d["key"].encode())
    resp = send_recv(json.dumps(req).encode(), ip)
    if not resp:
        print("no response")
        return 1
    try:
        res = decrypt_pack(resp, d["key"].encode())
    except Exception as e:
        print(f"response decrypt failed ({e})")
        return 1
    print("device replied:", json.dumps(res, ensure_ascii=False))
    if res.get("r") != 200:
        print("note: device returned r!=200 — check field names/values (see README parameter table)")
        return 1
    return 0


def main():
    p = argparse.ArgumentParser(description="Gree AC LAN control")
    sub = p.add_subparsers(dest="cmd", required=True)
    plist = sub.add_parser("list", help="discover devices (broadcast; add --sweep CIDR for unicast)")
    plist.add_argument("--sweep", metavar="CIDR", help="also unicast-scan a subnet, e.g. 192.168.1.0/24")
    pbind = sub.add_parser("bind", help="scan+bind one IP, save key to config")
    pbind.add_argument("ip")
    pbind.add_argument("--no-save", action="store_true", help="print the key instead of saving it")
    padd = sub.add_parser("add", help="manually add a device to config")
    padd.add_argument("ip")
    padd.add_argument("mac")
    padd.add_argument("key")
    ps = sub.add_parser("status")
    ps.add_argument("ip", nargs="?")
    pset = sub.add_parser("set")
    pset.add_argument("ip")
    pset.add_argument("kv", nargs="+", help="key=value pairs, e.g. Pow=1 SetTem=24")
    args = p.parse_args()
    return {"list": cmd_list, "bind": cmd_bind, "add": cmd_add, "status": cmd_status, "set": cmd_set}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
