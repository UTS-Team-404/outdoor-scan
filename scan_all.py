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

# Scapy
from scapy.all import sniff, RadioTap, Dot11, Dot11Elt, IP, TCP, UDP

# little helpy functions

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

# initial airodump scan (8secs by default)

def airodump_scan_8s(iface, band="bg", secs=8):
    """
    Run airodump-ng for `secs` seconds, writing CSV to a temp directory.
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
        print(f"[*] Scanning {iface} for {secs}s with airodump-ng…", end="", flush=True)
        for _ in range(secs):
            print(".", end="", flush=True)
            time.sleep(1)
        print()
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
    Return a list of AP dicts from an airodump CSV:
    {bssid, channel, power, privacy, cipher, auth, essid}
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
            try: ch = int(g(3))
            except: ch = None
            try: pwr = int(g(8))
            except: pwr = None
            priv, cip, auth, ess = g(5), g(6), g(7), g(13) or "<hidden>"
            aps.append({
                "bssid": bssid.lower(), "channel": ch, "power": pwr,
                "privacy": priv, "cipher": cip, "auth": auth, "essid": ess,
            })
    return aps

def pick_ap(aps):
    """
    Print a list and let the user choose an AP.
    """
    if not aps:
        print("[-] No APs found.")
        return None
    print("\nNearby Access Points:")
    for i, a in enumerate(aps, 1):
        sig = f"{a['power']} dBm" if a['power'] is not None else "N/A"
        ch = a['channel'] if a['channel'] is not None else "-"
        print(f"{i:2d}) {a['essid']:<24} ch={ch:>2}  {sig:>6}  {a['bssid']}  "
              f"({a['privacy']}/{a['cipher']}/{a['auth']})")
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

#CSV

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
        elt = pkt.getlayer(Dot11Elt, ID=0)  # SSID element
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

# GPS 

_gps_lat = None
_gps_lon = None
_gps_lock = Lock()

def gps_thread():
    """
    Keep _gps_lat/_gps_lon updated once per second.
    Prefer gpsd Python API; fall back to gpspipe.
    Works with gpsd fed by your phone over UDP.
    """
    global _gps_lat, _gps_lon
    # Try gpsd Python API first
    session = None
    try:
        from gps import gps, WATCH_ENABLE, WATCH_NEWSTYLE
        session = gps(mode=WATCH_ENABLE | WATCH_NEWSTYLE)
    except Exception:
        session = None

    if session is not None:
        # gpsd-py3 path
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
        # Fallback to gpspipe polling
        while True:
            try:
                out = subprocess.check_output(
                    ["gpspipe", "-w", "-n", "1"],
                    text=True, stderr=subprocess.DEVNULL
                )
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

# printing with scapy

def make_printer(target, sniff_type_value):
    """
    Return a function for scapy.sniff(prn=...) that filters to the chosen BSSID
    and prints a CSV line for each relevant frame.
    """
    bssid = target["bssid"]
    priv, cip, auth, ess = target["privacy"], target["cipher"], target["auth"], target["essid"]

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
            ts,           # captureTime
            src,          # srcMac
            dst,          # dstMac
            ssid,         # SSID
            priv or "NULL",
            cip or "NULL",
            auth or "NULL",
            glat,         # gpsLat
            glon,         # gpsLong
            rssi,         # strength
            str(length),  # contentLength
            ext,          # typeExternal
            itn,          # typeInternal
            ip_src,       # srcIP
            ip_dst,       # dstIP
            sp,           # srcPort
            dp,           # dstPort
            sniff_type_value  # sniffType ("internal" or "external")
        ]
        print(",".join(csvq(x) for x in row), flush=True)

    return prn

# main

def main():
    if os.geteuid() != 0:
        print("Run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="8s airodump scan -> choose AP -> Scapy targeted sniff (with GPS)."
    )
    parser.add_argument("iface", nargs="?", default="wlan1",
                        help="wireless interface (default: wlan1)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--internal", action="store_true",
                       help="set sniffType to 'internal'")
    group.add_argument("-e", "--external", action="store_true",
                       help="set sniffType to 'external'")
    args = parser.parse_args()

    iface = args.iface
    sniff_type_value = "internal" if (args.internal or not args.external) else "external"

    # 1) 8s discovery with airodump
    set_monitor(iface)
    csv_path = airodump_scan_8s(iface, band="bg", secs=8)
    if not csv_path:
        print("[-] airodump produced no CSV. Is the interface up & monitor-capable?")
        set_managed(iface)
        sys.exit(1)

    aps = parse_airodump_csv(csv_path)
    target = pick_ap(aps)
    if not target:
        print("No selection. Exiting.")
        set_managed(iface)
        sys.exit(0)

    print(f"\n[*] Target: {target['essid']}  {target['bssid']}  ch={target['channel']}")
    set_channel(iface, target["channel"])

    # 2) Start GPS thread (works with gpsd over UDP)
    threading.Thread(target=gps_thread, daemon=True).start()

    # 3) Print CSV header once
    header = [
        "captureTime","srcMac","dstMac","SSID",
        "privacy","cipher","auth","gpsLat","gpsLong",
        "strength","contentLength","typeExternal","typeInternal",
        "srcIP","dstIP","srcPort","dstPort","sniffType"
    ]
    print(",".join(header), flush=True)

    # 4) Live sniff with Scapy (until Ctrl+C)
    try:
        sniff(iface=iface, prn=make_printer(target, sniff_type_value), store=False)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        # Leave managed for convenience
        set_managed(iface)

if __name__ == "__main__":
    main()
