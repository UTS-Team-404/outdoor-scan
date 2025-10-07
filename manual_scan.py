#!/usr/bin/env python3

import argparse
import csv
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from threading import Lock

# scapy
from scapy.all import sniff, RadioTap, Dot11, Dot11Elt, IP, TCP, UDP

# ---------------------------- helpers ----------------------------

def run_quiet(cmd):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def set_monitor(iface):
    run_quiet(["ip", "link", "set", iface, "down"])
    run_quiet(["iw", "dev", iface, "set", "type", "monitor"])
    run_quiet(["ip", "link", "set", iface, "up"])
    time.sleep(0.2)

def set_managed(iface):
    run_quiet(["ip", "link", "set", iface, "down"])
    run_quiet(["iw", "dev", iface, "set", "type", "managed"])
    run_quiet(["ip", "link", "set", iface, "up"])
    time.sleep(0.2)

def set_channel(iface, ch):
    if ch:
        run_quiet(["iw", "dev", iface, "set", "channel", str(ch)])

# ----------------------- airodump (silent 3s) -----------------------

def airodump_scan_secs(iface, band="bg", secs=3):
    """
    Run airodump-ng for `secs` seconds silently (no printing).
    Return path to the first CSV produced (or None).
    """
    tmpd = tempfile.mkdtemp(prefix="airodump_")
    base = os.path.join(tmpd, "scan")
    proc = subprocess.Popen(
        ["airodump-ng", "--band", band, "--write-interval", "1",
         "--output-format", "csv", "--write", base, iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid
    )
    try:
        time.sleep(secs)
    finally:
        # gentle stop
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    csvs = [os.path.join(tmpd, f) for f in os.listdir(tmpd) if f.endswith(".csv")]
    csvs.sort()
    return csvs[0] if csvs else None

def parse_airodump_csv(csv_path):
    """
    Return list of AP dicts: {bssid, channel, power, privacy, cipher, auth, essid}
    """
    if not csv_path or not os.path.exists(csv_path):
        return []
    with open(csv_path, newline="", encoding="utf-8", errors="ignore") as fh:
        rows = list(csv.reader(fh))
    aps, in_ap = [], False
    for r in rows:
        if not r:
            continue
        if r[0].strip() == "BSSID":
            in_ap = True
            continue
        if r[0].strip().startswith("Station MAC"):
            break
        if in_ap:
            def g(i): return r[i].strip() if i < len(r) else ""
            bssid = g(0)
            if not bssid:
                continue
            try:
                ch = int(g(3))
            except:
                ch = None
            try:
                pwr = int(g(8))
            except:
                pwr = None
            priv, cip, auth, ess = g(5), g(6), g(7), g(13) or "<hidden>"
            aps.append({
                "bssid": bssid.lower(),
                "channel": ch,
                "power": pwr,
                "privacy": priv,
                "cipher": cip,
                "auth": auth,
                "essid": ess,
            })
    return aps

def pick_ap(aps):
    if not aps:
        print("[-] No APs found.")
        return None
    print("\nNearby Access Points:")
    for i, a in enumerate(aps, 1):
        sig = f"{a['power']} dBm" if a['power'] is not None else "N/A"
        ch = a['channel'] if a['channel'] is not None else "-"
        print(f"{i:2d}) {a['essid']:<24} ch={ch:>2}  {sig:>6}  {a['bssid']}  ({a['privacy']}/{a['cipher']}/{a['auth']})")
    s = input("\nSelect number (Enter to cancel): ").strip()
    if not s:
        return None
    try:
        idx = int(s) - 1
        if 0 <= idx < len(aps):
            return aps[idx]
    except Exception:
        pass
    print("[-] Invalid choice.")
    return None

# ------------------------- CSV helpers -------------------------

def csvq(s):
    if s is None: return "NULL"
    s = str(s)
    if any(c in s for c in [",", '"', "\n"]):
        s = '"' + s.replace('"', '""') + '"'
    return s

def rssi_from(pkt):
    try:
        if hasattr(pkt, "dBm_AntSignal") and pkt.dBm_AntSignal is not None:
            return str(int(pkt.dBm_AntSignal))
        rt = pkt.getlayer(RadioTap)
        if rt and "dBm_AntSignal" in rt.fields and rt.fields["dBm_AntSignal"] is not None:
            return str(int(rt.fields["dBm_AntSignal"]))
    except Exception:
        pass
    return "NULL"

def ssid_from(pkt):
    try:
        elt = pkt.getlayer(Dot11Elt, ID=0)
        if elt and elt.info is not None:
            return elt.info.decode("utf-8", errors="ignore")
    except Exception:
        pass
    return "<hidden>"

def ip_ports(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src = getattr(ip, "src", "NULL")
        dst = getattr(ip, "dst", "NULL")
        sp = dp = "NULL"
        if pkt.haslayer(TCP):
            sp, dp = str(pkt[TCP].sport), str(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            sp, dp = str(pkt[UDP].sport), str(pkt[UDP].dport)
        return src, dst, sp, dp
    return "NULL", "NULL", "NULL", "NULL"

# ----------------------------- GPS ---------------------------------

_gps_lat = None
_gps_lon = None
_gps_lock = Lock()

def gps_thread():
    global _gps_lat, _gps_lon
    session = None
    try:
        from gps import gps, WATCH_ENABLE, WATCH_NEWSTYLE
        session = gps(mode=WATCH_ENABLE | WATCH_NEWSTYLE)
    except Exception:
        session = None

    if session is not None:
        while True:
            try:
                report = session.next()
                if report and getattr(report, 'class', None) == 'TPV':
                    lat = getattr(report, 'lat', None)
                    lon = getattr(report, 'lon', None)
                    with _gps_lock:
                        _gps_lat = float(lat) if lat is not None else None
                        _gps_lon = float(lon) if lon is not None else None
            except KeyboardInterrupt:
                break
            except Exception:
                time.sleep(0.25)
            time.sleep(0.2)
    else:
        while True:
            try:
                out = subprocess.check_output(["gpspipe", "-w", "-n", "1"], text=True, stderr=subprocess.DEVNULL)
                lat = lon = None
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("class") == "TPV":
                        lat = obj.get("lat")
                        lon = obj.get("lon")
                with _gps_lock:
                    _gps_lat = float(lat) if lat is not None else None
                    _gps_lon = float(lon) if lon is not None else None
            except KeyboardInterrupt:
                break
            except Exception:
                with _gps_lock:
                    _gps_lat = None
                    _gps_lon = None
            time.sleep(1.0)

# --------------------------- scapy printer ---------------------------

def make_printer(target, sniff_type_value):
    bssid = target["bssid"]
    priv, cip, auth, ess = target.get("privacy"), target.get("cipher"), target.get("auth"), target.get("essid")

    def relevant(pkt):
        if not pkt.haslayer(Dot11):
            return False
        a1 = (getattr(pkt, "addr1", "") or "").lower()
        a2 = (getattr(pkt, "addr2", "") or "").lower()
        a3 = (getattr(pkt, "addr3", "") or "").lower()
        return bssid in (a1, a2, a3)

    def prn(pkt):
        if not relevant(pkt):
            return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = getattr(pkt, "addr2", "NULL") or "NULL"
        dst = getattr(pkt, "addr1", "NULL") or "NULL"
        ssid = ssid_from(pkt)
        rssi = rssi_from(pkt)
        length = len(pkt) if pkt else 0
        ext = {0: "management", 1: "control", 2: "data"}.get(getattr(pkt, "type", None), "unknown")
        itn = str(getattr(pkt, "subtype", "unk"))
        ip_src, ip_dst, sp, dp = ip_ports(pkt)
        with _gps_lock:
            glat = _gps_lat if _gps_lat is not None else "NULL"
            glon = _gps_lon if _gps_lon is not None else "NULL"
        row = [
            ts, src, dst, ssid,
            priv or "UNKNOWN", cip or "UNKNOWN", auth or "UNKNOWN",
            glat, glon, rssi, str(length), ext, itn,
            ip_src, ip_dst, sp, dp, sniff_type_value
        ]
        print(",".join(csvq(x) for x in row), flush=True)

    return prn

# ----------------------------- main ------------------------------------

def main():
    if os.geteuid() != 0:
        print("Run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="3s airodump -> scapy targeted sniff (bssid option)")
    parser.add_argument("iface", nargs="?", default="wlan1", help="wireless interface (default wlan1)")
    parser.add_argument("--bssid", help="BSSID to target (format aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--channel", type=int, help="channel for the provided BSSID (optional if airodump finds it)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--internal", action="store_true", help="set sniffType to 'internal'")
    group.add_argument("-e", "--external", action="store_true", help="set sniffType to 'external'")
    args = parser.parse_args()

    iface = args.iface
    sniff_type_value = "internal" if (args.internal or not args.external) else "external"

    # Ensure monitor before initial airodump
    set_monitor(iface)
    csv_path = airodump_scan_secs(iface, band="bg", secs=3)
    if not csv_path:
        print("[-] airodump produced no CSV. Is the interface up & monitor-capable?")
        set_managed(iface)
        sys.exit(1)

    aps = parse_airodump_csv(csv_path)

    target = None
    if args.bssid:
        want = args.bssid.lower()
        found = next((a for a in aps if a.get("bssid") == want), None)
        if found:
            target = found
        else:
            if args.channel:
                target = {
                    "bssid": want,
                    "channel": args.channel,
                    "essid": "<unknown>",
                    "privacy": "UNKNOWN",
                    "cipher": "UNKNOWN",
                    "auth": "UNKNOWN",
                    "power": None
                }
            else:
                print(f"[-] BSSID {want} not found in airodump results and no --channel provided. Can't proceed safely.")
                set_managed(iface)
                sys.exit(1)
    else:
        target = pick_ap(aps)
        if not target:
            set_managed(iface)
            sys.exit(0)

    # lock to channel (if provided)
    set_channel(iface, target.get("channel"))

    # start gps thread
    threading.Thread(target=gps_thread, daemon=True).start()

    # print header only (then stream rows)
    header = [
        "captureTime","srcMac","dstMac","SSID",
        "privacy","cipher","auth","gpsLat","gpsLong",
        "strength","contentLength","typeExternal","typeInternal",
        "srcIP","dstIP","srcPort","dstPort","sniffType"
    ]
    print(",".join(header), flush=True)

    try:
        sniff(iface=iface, prn=make_printer(target, sniff_type_value), store=False)
    except KeyboardInterrupt:
        pass
    finally:
        set_managed(iface)

if __name__ == "__main__":
    main()
