import time
import datetime
import socket
import subprocess
import psutil
import re
import os

GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
CYAN = "\033[96m"; WHITE = "\033[97m"; DIM = "\033[2m"
RESET = "\033[0m"; BOLD = "\033[1m"

known_devices = {}
known_usb_devices = set()
last_scan_error = ""


def divider(char="─", width=70, color=CYAN):
    return f"{color}{char * width}{RESET}"


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def scan_network_nmap(network):
    global last_scan_error
    last_scan_error = ""
    try:
        cmd = ["nmap", "-sn", network]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            last_scan_error = f"Nmap exited with code {result.returncode}: {result.stderr.strip()[:120]}"
            return []

        devices = []
        ip = None
        mac = None

        def flush(ip, mac):
            if ip:
                hostname = resolve_hostname(ip)
                devices.append({"ip": ip, "mac": mac if mac else "Unknown", "hostname": hostname})

        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                # save the previous host before we start tracking the new one
                flush(ip, mac)
                match = re.search(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', line)
                if match:
                    ip = match.group(1)
                else:
                    parts = line.split()
                    ip = parts[-1].strip("()") if parts else None
                mac = None
            elif "MAC Address:" in line:
                parts = line.split()
                for part in parts:
                    if ":" in part and len(part) == 17:
                        mac = part
                        break

        flush(ip, mac)  # don't drop the last host in the output
        return devices

    except FileNotFoundError:
        last_scan_error = "nmap not found - install it with: sudo apt install nmap"
        return []
    except subprocess.TimeoutExpired:
        last_scan_error = "Nmap scan timed out."
        return []
    except Exception as e:
        last_scan_error = f"Nmap scan error: {e}"
        return []


def detect_new_devices(devices):
    new = []
    for d in devices:
        if d["ip"] not in known_devices:
            known_devices[d["ip"]] = d["mac"]
            new.append(d)
    return new


def detect_arp_spoofing(devices):
    alerts = []
    for d in devices:
        old_mac = known_devices.get(d["ip"])
        if old_mac and d["mac"] != "Unknown" and old_mac != "Unknown" and old_mac != d["mac"]:
            alerts.append(d)
            known_devices[d["ip"]] = d["mac"]
    return alerts


def detect_usb_devices():
    global known_usb_devices
    try:
        result = subprocess.run(["lsusb"], capture_output=True, text=True, check=True, timeout=5)
        current = set(result.stdout.splitlines())
        added = current - known_usb_devices
        removed = known_usb_devices - current
        known_usb_devices = current
        return list(added), list(removed)
    except:
        return [], []


def get_network_speed():
    try:
        n1 = psutil.net_io_counters()
        time.sleep(1)
        n2 = psutil.net_io_counters()
        up = round(((n2.bytes_sent - n1.bytes_sent) * 8) / 1_000_000, 2)
        down = round(((n2.bytes_recv - n1.bytes_recv) * 8) / 1_000_000, 2)
        return up, down
    except:
        return 0.0, 0.0


def get_network_info():
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        if iface == "lo":
            continue
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                netmask = addr.netmask
                if netmask:
                    prefix = sum(bin(int(x)).count("1") for x in netmask.split('.'))
                else:
                    prefix = 24
                ip_parts = ip.split('.')
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/{prefix}"
                return network, iface
    return "192.168.1.0/24", None


if __name__ == "__main__":
    scan_count = 0
    network, iface = get_network_info()
    print(f"{CYAN}Network: {network} | Interface: {iface}{RESET}")

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{YELLOW}Warning: not running as root. Full host discovery and MAC "
              f"addresses usually need root on Linux. Re-run with: sudo python3 {os.path.basename(__file__)}{RESET}")
        time.sleep(2)

    while True:
        scan_count += 1
        now = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        devices = scan_network_nmap(network)
        new_devices = detect_new_devices(devices) if devices else []
        arp_alerts = detect_arp_spoofing(devices) if devices else []
        usb_added, usb_removed = detect_usb_devices()
        up_mbps, dn_mbps = get_network_speed()

        print("\033c", end="")

        print(divider("═"))
        print(f"{CYAN}{BOLD}{'509 ARMY BASE - NETWORK MONITORING':^70}{RESET}")
        print(divider("═"))
        print(f"{DIM}Scan #{scan_count:<4} | {now} | Range: {network}{RESET}\n")

        print(f"{BOLD}SCAN SUMMARY{RESET}")
        print(f"{'Devices Found':<25}: {CYAN}{len(devices)}{RESET}")
        print(f"{'New Devices':<25}: {GREEN}{len(new_devices)}{RESET}")
        print(f"{'ARP Alerts':<25}: {(RED if arp_alerts else GREEN)}{len(arp_alerts)}{RESET}")
        print(f"{'Upload Speed':<25}: {CYAN}{up_mbps} Mbps{RESET}")
        print(f"{'Download Speed':<25}: {CYAN}{dn_mbps} Mbps{RESET}")
        if last_scan_error:
            print(f"{'Last Scan Error':<25}: {RED}{last_scan_error}{RESET}")

        print("\n" + divider())

        print(f"\n{BOLD}DEVICES ON NETWORK{RESET}")
        print(f"{'IP Address':<18} {'MAC Address':<20} {'Hostname':<25} {'Status'}")
        print("-" * 70)

        for d in devices:
            status = "[NEW]" if d in new_devices else ""
            print(
                f"{d['ip']:<18} "
                f"{d['mac']:<20} "
                f"{d['hostname'][:24]:<25} "
                f"{status}"
            )

        if usb_added or usb_removed:
            print("\n" + divider())
            print(f"\n{BOLD}USB ACTIVITY{RESET}")
            for dev in usb_added:
                print(f"{GREEN}[CONNECTED]{RESET} {dev}")
            for dev in usb_removed:
                print(f"{RED}[REMOVED]{RESET}   {dev}")

        print("\n" + divider("═"))
        print(f"{DIM}Next scan in 10 seconds...{RESET}")
        print(divider("═"))

        time.sleep(10)
