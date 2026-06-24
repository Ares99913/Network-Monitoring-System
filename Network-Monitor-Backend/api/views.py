"""
509 ARMY BASE — REST API Views
All monitoring endpoints for frontend consumption.
"""

import os
import time
import datetime
import socket
import uuid
import subprocess
import threading
import re
import hashlib
import sqlite3

import psutil
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

# ─── Brute‑force settings ─────────────────────────────
MAX_ATTEMPTS         = 4       # Ban after 4 wrong attempts
BAN_DURATION_SEC     = 300     # 5 minutes ban
MONITOR_WINDOW_SEC   = 60      # Watch window
SUSPICIOUS_THRESHOLD = 3       # Warning after 3 attempts

_attempt_log = {}   # {ip: [timestamp, ...]}
_banned_ips  = {}   # {ip: {banned_at, attempts, username, reason}}
_bf_lock     = threading.Lock()

def _clean_old_attempts(ip):
    cutoff = time.time() - MONITOR_WINDOW_SEC
    _attempt_log[ip] = [t for t in _attempt_log.get(ip, []) if t >= cutoff]

def _expire_bans():
    if BAN_DURATION_SEC == 0:
        return
    expired = [ip for ip, info in _banned_ips.items()
               if time.time() - info["banned_at"] >= BAN_DURATION_SEC]
    for ip in expired:
        _banned_ips.pop(ip, None)
        _attempt_log.pop(ip, None)

def _get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')

# ═══════════════════════════════════════════════════════════════════════
# 1. SYSTEM MONITORING  —  GET /api/system-status/
# ═══════════════════════════════════════════════════════════════════════

def _get_cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                for entry in entries:
                    if entry.current and entry.current > 0:
                        return entry.current
    except Exception:
        pass
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read()) / 1000, 1)
    except Exception:
        pass
    return None

def _get_server_status():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('apache2', 'nginx', 'httpd', 'lighttpd'):
            return "Online", "OK"
    return "Offline", "CRITICAL"

def _get_database_status():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('mysqld', 'postgres', 'mongod', 'redis-server', 'mariadbd'):
            return "Connected", "OK"
    return "Disconnected", "CRITICAL"

def _get_firewall_status():
    try:
        out = subprocess.getoutput("ufw status")
        if "active" in out.lower():
            return "Protected", "OK"
    except Exception:
        pass
    try:
        out = subprocess.getoutput("systemctl is-active firewalld")
        if out.strip() == "active":
            return "Protected", "OK"
    except Exception:
        pass
    return "Inactive", "WARN"

def _get_open_ports():
    ports = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                if port not in ports:
                    ports.append(port)
        ports.sort()
    except Exception:
        pass
    return ports

@api_view(['GET'])
def get_system_status(request):
    """System Monitoring — CPU, RAM, Disk, Temp, Services, Ports"""
    hostname = socket.gethostname()
    try:
        ip_address = subprocess.getoutput("hostname -I").split()[0]
    except Exception:
        ip_address = "Not Available"

    mac_address = ':'.join(
        ('%012X' % uuid.getnode())[i:i+2] for i in range(0, 12, 2)
    )

    cpu_usage  = psutil.cpu_percent(interval=0.1)
    ram        = psutil.virtual_memory()
    disk       = psutil.disk_usage('/')

    cpu_temp = _get_cpu_temp()
    server_val, server_st     = _get_server_status()
    db_val, db_st             = _get_database_status()
    firewall_val, firewall_st = _get_firewall_status()
    open_ports                = _get_open_ports()

    if cpu_temp is None:
        temp_val, temp_st = "45°C", "OK"
    elif cpu_temp >= 85:
        temp_val, temp_st = f"{cpu_temp}°C", "CRITICAL"
    elif cpu_temp >= 70:
        temp_val, temp_st = f"{cpu_temp}°C", "WARN"
    else:
        temp_val, temp_st = f"{cpu_temp}°C", "OK"

    alerts   = sum(1 for s in [server_st, db_st, firewall_st, temp_st] if s == "CRITICAL")
    alert_st = "OK" if alerts == 0 else ("WARN" if alerts == 1 else "CRITICAL")

    return Response({
        "timestamp": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "device_info": {
            "hostname":    hostname,
            "ip_address":  ip_address,
            "mac_address": mac_address,
        },
        "system_usage": {
            "cpu_usage":        cpu_usage,
            "ram_usage":        ram.percent,
            "ram_total_gb":     round(ram.total / (1024**3), 2),
            "ram_used_gb":      round(ram.used / (1024**3), 2),
            "disk_usage":       disk.percent,
            "disk_total_gb":    round(disk.total / (1024**3), 2),
            "disk_used_gb":     round(disk.used / (1024**3), 2),
        },
        "health_status": {
            "server":          {"value": server_val,   "status": server_st},
            "database":        {"value": db_val,       "status": db_st},
            "firewall":        {"value": firewall_val, "status": firewall_st},
            "cpu_temperature": {"value": temp_val,     "status": temp_st},
            "critical_alerts": {"value": alerts,       "status": alert_st},
        },
        "open_ports": {
            "ports":           open_ports,
            "total_listening":  len(open_ports),
        },
    })


# ═══════════════════════════════════════════════════════════════════════
# 2. NETWORK MONITORING  —  GET /api/network-status/
# ═══════════════════════════════════════════════════════════════════════

_prev_net = {
    "sent":  psutil.net_io_counters().bytes_sent,
    "recv":  psutil.net_io_counters().bytes_recv,
    "time":  time.time(),
}

def _get_primary_ip():
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    return "Not Available"

def _get_mac_address():
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == psutil.AF_LINK and addr.address and addr.address != "00:00:00:00:00:00":
                return addr.address
    mac = uuid.getnode()
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))

def _bytes_to_mb(b):
    return round(b / (1024 * 1024), 2)

def _bytes_to_gb(b):
    return round(b / (1024 * 1024 * 1024), 3)

@api_view(['GET'])
def get_network_status(request):
    """Network Monitoring — Throughput, Interfaces, Connections"""
    global _prev_net

    hostname    = socket.gethostname()
    ip_address  = _get_primary_ip()
    mac_address = _get_mac_address()

    net_io = psutil.net_io_counters()
    now    = time.time()
    elapsed = max(now - _prev_net["time"], 0.001)

    up_mbps   = round(((net_io.bytes_sent - _prev_net["sent"]) * 8) / (elapsed * 1_000_000), 2)
    down_mbps = round(((net_io.bytes_recv - _prev_net["recv"]) * 8) / (elapsed * 1_000_000), 2)

    _prev_net["sent"] = net_io.bytes_sent
    _prev_net["recv"] = net_io.bytes_recv
    _prev_net["time"] = now

    total_sent = _bytes_to_mb(net_io.bytes_sent)
    total_recv = _bytes_to_mb(net_io.bytes_recv)
    total_gb   = _bytes_to_gb(net_io.bytes_sent + net_io.bytes_recv)

    # Interfaces
    interfaces_data = []
    if_stats = psutil.net_if_stats()
    if_addrs = psutil.net_if_addrs()

    for iface, stats in if_stats.items():
        iface_ip = "—"
        if iface in if_addrs:
            for a in if_addrs[iface]:
                if a.family == socket.AF_INET:
                    iface_ip = a.address
                    break
        interfaces_data.append({
            "name":   iface,
            "is_up":  stats.isup,
            "speed":  stats.speed,
            "mtu":    stats.mtu,
            "ip":     iface_ip,
        })

    # Active connections
    try:
        connections = psutil.net_connections(kind="inet")
        established = [c for c in connections if c.status == "ESTABLISHED"]
        listening   = [c for c in connections if c.status == "LISTEN"]
        time_wait   = [c for c in connections if c.status == "TIME_WAIT"]

        top_connections = []
        seen = set()
        for c in established[:10]:
            if c.raddr:
                key = (c.raddr.ip, c.raddr.port)
                if key not in seen:
                    seen.add(key)
                    top_connections.append({
                        "remote_ip":   c.raddr.ip,
                        "remote_port": c.raddr.port,
                        "protocol":    "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    })

        connections_summary = {
            "established":    len(established),
            "listening":      len(listening),
            "time_wait":      len(time_wait),
            "total_sockets":  len(connections),
            "top_connections": top_connections,
        }
    except Exception:
        connections_summary = {"error": "Permission denied — run with sudo"}

    return Response({
        "timestamp": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "device_identity": {
            "hostname":    hostname,
            "ip_address":  ip_address,
            "mac_address": mac_address,
        },
        "live_throughput": {
            "upload_mbps":   up_mbps,
            "download_mbps": down_mbps,
        },
        "total_data_transfer": {
            "data_sent_mb":     total_sent,
            "data_received_mb": total_recv,
            "total_traffic_gb": total_gb,
        },
        "packets": {
            "packets_sent":     net_io.packets_sent,
            "packets_received": net_io.packets_recv,
        },
        "interfaces":  interfaces_data,
        "connections":  connections_summary,
    })


# ═══════════════════════════════════════════════════════════════════════
# 3. DEVICE SCANNING  —  GET /api/device-scan/
# ═══════════════════════════════════════════════════════════════════════

_known_devices = {}
_known_usb     = set()

def _get_network_info():
    addrs = psutil.net_if_addrs()

    for iface, addr_list in addrs.items():
        if iface == "lo":
            continue

        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                netmask = addr.netmask

                prefix = sum(
                    bin(int(x)).count("1")
                    for x in netmask.split(".")
                ) if netmask else 24

                parts = ip.split(".")
                network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/{prefix}"

                return network, iface

    return "192.168.1.0/24", None

def _resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def _scan_network_nmap(network):
    try:
        cmd    = ["nmap", "-sn", network]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return [], f"Nmap exited with code {result.returncode}"

        devices = []
        ip = mac = None

        def flush(ip, mac):
            if ip:
                hostname = _resolve_hostname(ip)
                devices.append({"ip": ip, "mac": mac or "Unknown", "hostname": hostname})

        for line in result.stdout.splitlines():
            if "Nmap scan report for" in line:
                flush(ip, mac)
                match = re.search(r'\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)', line)
                ip    = match.group(1) if match else line.split()[-1].strip("()")
                mac   = None
            elif "MAC Address:" in line:
                parts = line.split()
                for part in parts:
                    if ":" in part and len(part) == 17:
                        mac = part
                        break

        flush(ip, mac)
        return devices, ""

    except FileNotFoundError:
        return [], "nmap not found — install with: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return [], "Nmap scan timed out"
    except Exception as e:
        return [], str(e)

def _detect_usb_devices():
    try:
        result  = subprocess.run(["lsusb"], capture_output=True, text=True, check=True, timeout=5)
        current = set(result.stdout.splitlines())
        added   = list(current - _known_usb)
        removed = list(_known_usb - current)
        _known_usb.clear()
        _known_usb.update(current)
        return list(current), added, removed
    except Exception:
        return [], [], []

@api_view(['GET'])
def get_device_scan(request):
    """Device Scanning — Nmap network devices + USB activity"""
    global _known_devices

    network, iface = _get_network_info()
    devices, error = _scan_network_nmap(network)

    # Detect new devices
    new_devices = []
    for d in devices:
        if d["ip"] not in _known_devices:
            _known_devices[d["ip"]] = d["mac"]
            new_devices.append(d)

    # ARP spoofing detection
    arp_alerts = []
    for d in devices:
        old_mac = _known_devices.get(d["ip"])
        if old_mac and d["mac"] != "Unknown" and old_mac != "Unknown" and old_mac != d["mac"]:
            arp_alerts.append({
                "ip":      d["ip"],
                "old_mac": old_mac,
                "new_mac": d["mac"],
            })
            _known_devices[d["ip"]] = d["mac"]

    # USB
    usb_all, usb_added, usb_removed = _detect_usb_devices()

    # Network speed
    try:
        n1 = psutil.net_io_counters()
        time.sleep(1)
        n2 = psutil.net_io_counters()
        up   = round(((n2.bytes_sent - n1.bytes_sent) * 8) / 1_000_000, 2)
        down = round(((n2.bytes_recv - n1.bytes_recv) * 8) / 1_000_000, 2)
    except Exception:
        up = down = 0.0

    return Response({
        "timestamp":  datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "network":    network,
        "interface":  iface,
        "scan_error": error,
        "scan_summary": {
            "devices_found": len(devices),
            "new_devices":   len(new_devices),
            "arp_alerts":    len(arp_alerts),
            "upload_mbps":   up,
            "download_mbps": down,
        },
        "devices":     devices,
        "new_devices": new_devices,
        "arp_alerts":  arp_alerts,
        "usb": {
            "all_devices":      usb_all,
            "newly_connected":  usb_added,
            "recently_removed": usb_removed,
        },
    })


# ═══════════════════════════════════════════════════════════════════════
# 4. ALERT MANAGEMENT  —  GET /api/alert-status/
# ═══════════════════════════════════════════════════════════════════════

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5900, 6666, 7777, 8080, 9090}

_cooldowns      = {}
_session_counts = {"INFO": 0, "WARN": 0, "CRITICAL": 0}
_alert_history  = []

COOLDOWN_SECONDS = {
    "CPU_HIGH": 60, "RAM_HIGH": 60, "DISK_HIGH": 120,
    "TEMP_WARN": 60, "TEMP_CRITICAL": 30, "FIREWALL": 120,
    "SERVER_DOWN": 30, "DB_DOWN": 30,
    "PORT_SUSPICIOUS": 60, "HIGH_BANDWIDTH": 30, "TOO_MANY_SOCKETS": 60,
}

def _can_alert(key):
    cooldown = COOLDOWN_SECONDS.get(key, 60)
    last     = _cooldowns.get(key, 0)
    if time.time() - last >= cooldown:
        _cooldowns[key] = time.time()
        return True
    return False

def _check_system_alerts():
    alerts = []

    cpu = psutil.cpu_percent(interval=0.1)
    if cpu >= 90 and _can_alert("CPU_HIGH"):
        alerts.append({"level": "CRITICAL", "message": f"CPU Usage Critical — {cpu}%"})
    elif cpu >= 75 and _can_alert("CPU_HIGH"):
        alerts.append({"level": "WARN", "message": f"CPU Usage High — {cpu}%"})

    ram = psutil.virtual_memory().percent
    if ram >= 90 and _can_alert("RAM_HIGH"):
        alerts.append({"level": "CRITICAL", "message": f"RAM Usage Critical — {ram}%"})
    elif ram >= 80 and _can_alert("RAM_HIGH"):
        alerts.append({"level": "WARN", "message": f"RAM Usage High — {ram}%"})

    disk = psutil.disk_usage('/').percent
    if disk >= 95 and _can_alert("DISK_HIGH"):
        alerts.append({"level": "CRITICAL", "message": f"Disk Usage Critical — {disk}%"})
    elif disk >= 85 and _can_alert("DISK_HIGH"):
        alerts.append({"level": "WARN", "message": f"Disk Usage High — {disk}%"})

    # Temperature
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                for entry in entries:
                    if entry.current and entry.current > 0:
                        t = entry.current
                        if t >= 85 and _can_alert("TEMP_CRITICAL"):
                            alerts.append({"level": "CRITICAL", "message": f"CPU Temp Critical — {t}°C"})
                        elif t >= 70 and _can_alert("TEMP_WARN"):
                            alerts.append({"level": "WARN", "message": f"CPU Temp High — {t}°C"})
                        break
    except Exception:
        pass

    # Firewall
    fw_ok = False
    try:
        out = subprocess.getoutput("ufw status")
        if "active" in out.lower():
            fw_ok = True
    except Exception:
        pass
    if not fw_ok and _can_alert("FIREWALL"):
        alerts.append({"level": "CRITICAL", "message": "Firewall Inactive — System Unprotected"})

    # Web server
    server_ok = any(p.info['name'] in ('apache2', 'nginx', 'httpd', 'lighttpd')
                    for p in psutil.process_iter(['name']))
    if not server_ok and _can_alert("SERVER_DOWN"):
        alerts.append({"level": "WARN", "message": "Web Server Offline"})

    # Database
    db_ok = any(p.info['name'] in ('mysqld', 'postgres', 'mongod', 'redis-server', 'mariadbd')
                for p in psutil.process_iter(['name']))
    if not db_ok and _can_alert("DB_DOWN"):
        alerts.append({"level": "WARN", "message": "Database Disconnected"})

    # Suspicious ports
    try:
        conns = psutil.net_connections(kind='inet')
        listening_ports = {c.laddr.port for c in conns if c.status == 'LISTEN' and c.laddr}
        for port in listening_ports:
            if port in SUSPICIOUS_PORTS and _can_alert("PORT_SUSPICIOUS"):
                alerts.append({"level": "WARN", "message": f"Suspicious Port Open — {port}"})
    except Exception:
        pass

    return alerts

def _check_network_alerts():
    alerts = []
    try:
        conns = psutil.net_connections(kind='inet')
        if len(conns) > 200 and _can_alert("TOO_MANY_SOCKETS"):
            alerts.append({"level": "WARN", "message": f"Too Many Open Sockets — {len(conns)}"})

        n1 = psutil.net_io_counters()
        time.sleep(0.5)
        n2 = psutil.net_io_counters()
        up = round(((n2.bytes_sent - n1.bytes_sent) * 8) / (0.5 * 1_000_000), 2)
        dn = round(((n2.bytes_recv - n1.bytes_recv) * 8) / (0.5 * 1_000_000), 2)
        if (up > 100 or dn > 100) and _can_alert("HIGH_BANDWIDTH"):
            alerts.append({"level": "WARN", "message": f"High Bandwidth — Up: {up} Mbps  Down: {dn} Mbps"})
    except Exception:
        pass
    return alerts

@api_view(['GET'])
def get_alert_status(request):
    """Alert Management — System + Network alerts with cooldowns"""
    sys_alerts = _check_system_alerts()
    net_alerts = _check_network_alerts()
    all_alerts = sys_alerts + net_alerts

    for a in all_alerts:
        level = a["level"]
        if level in _session_counts:
            _session_counts[level] += 1

    if not all_alerts:
        _session_counts["INFO"] += 1

    ts = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    for a in all_alerts:
        _alert_history.append({"timestamp": ts, **a})
    if len(_alert_history) > 100:
        del _alert_history[:len(_alert_history) - 100]

    cpu  = psutil.cpu_percent()
    ram  = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    return Response({
        "timestamp":       ts,
        "all_systems_ok":  len(all_alerts) == 0,
        "active_alerts":   all_alerts,
        "live_status": {
            "cpu_usage":  cpu,
            "ram_usage":  ram,
            "disk_usage": disk,
        },
        "session_summary": {
            "critical": _session_counts["CRITICAL"],
            "warn":     _session_counts["WARN"],
            "info":     _session_counts["INFO"],
        },
        "recent_history": _alert_history[-20:],
    })


# ═══════════════════════════════════════════════════════════════════════
# 5. BRUTE FORCE DETECTION  —  /api/brute-force/*
# ═══════════════════════════════════════════════════════════════════════

@api_view(['GET'])
def get_brute_force_status(request):
    """Brute Force Monitor — Banned IPs + Suspicious activity"""
    with _bf_lock:
        _expire_bans()

        banned_list = []
        for ip, info in _banned_ips.items():
            elapsed   = int(time.time() - info["banned_at"])
            remaining = max(0, BAN_DURATION_SEC - elapsed) if BAN_DURATION_SEC > 0 else "permanent"
            banned_list.append({
                "ip":            ip,
                "banned_at":     datetime.datetime.fromtimestamp(info["banned_at"]).strftime("%H:%M:%S"),
                "attempts":      info["attempts"],
                "last_user":     info.get("username", "unknown"),
                "remaining_sec": remaining,
            })

        suspects = {}
        for ip, timestamps in _attempt_log.items():
            if ip not in _banned_ips:
                _clean_old_attempts(ip)
                count = len(_attempt_log.get(ip, []))
                if count >= SUSPICIOUS_THRESHOLD:
                    suspects[ip] = count

    return Response({
        "timestamp": datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "policy": {
            "max_attempts":        MAX_ATTEMPTS,
            "monitor_window_sec":  MONITOR_WINDOW_SEC,
            "ban_duration_sec":    BAN_DURATION_SEC,
        },
        "banned_ips": {
            "count": len(banned_list),
            "list":  banned_list,
        },
        "suspicious_activity": {
            "count": len(suspects),
            "list":  [{"ip": ip, "failed_attempts": cnt, "max": MAX_ATTEMPTS}
                      for ip, cnt in suspects.items()],
        },
    })


@api_view(['POST'])
def record_brute_force_attempt(request):
    """Record a failed login attempt — POST {ip, username}"""
    ip       = request.data.get("ip", "unknown")
    username = request.data.get("username", "unknown")

    with _bf_lock:
        _expire_bans()
        now = time.time()

        if ip in _banned_ips:
            info    = _banned_ips[ip]
            elapsed = now - info["banned_at"]
            remaining = max(0, int(BAN_DURATION_SEC - elapsed)) if BAN_DURATION_SEC > 0 else "permanent"
            return Response({
                "status":   "blocked",
                "attempts": info["attempts"],
                "message":  f"IP {ip} is banned — {remaining}s remaining",
            })

        _attempt_log.setdefault(ip, []).append(now)
        _clean_old_attempts(ip)
        count = len(_attempt_log[ip])

        if count >= MAX_ATTEMPTS:
            _banned_ips[ip] = {
                "banned_at": now,
                "attempts":  count,
                "username":  username,
                "reason":    f"{count} failed login attempts",
            }
            return Response({
                "status":   "blocked",
                "attempts": count,
                "message":  f"IP {ip} BANNED after {count} failed attempts. Contact support to unblock.",
            })

        elif count >= SUSPICIOUS_THRESHOLD:
            return Response({
                "status":   "warn",
                "attempts": count,
                "message":  f"Warning: {count} failed attempt(s). {MAX_ATTEMPTS - count} left before ban.",
            })

        else:
            return Response({
                "status":   "ok",
                "attempts": count,
                "message":  f"Incorrect credentials. {MAX_ATTEMPTS - count} attempt(s) remaining.",
            })


@api_view(['POST'])
def unban_ip(request):
    """Manually unban an IP — POST {ip}"""
    ip = request.data.get("ip", "")

    with _bf_lock:
        if ip in _banned_ips:
            _banned_ips.pop(ip, None)
            _attempt_log.pop(ip, None)
            return Response({"status": "success", "message": f"IP {ip} has been unbanned."})
        else:
            return Response({"status": "not_found", "message": f"IP {ip} is not in the ban list."})


# ═══════════════════════════════════════════════════════════════════════
# 6. USER AUTHENTICATION  —  register_user / login_user (SQLite DB)
# ═══════════════════════════════════════════════════════════════════════

def _init_users_db():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            first_name TEXT NOT NULL,
            middle_name TEXT,
            last_name TEXT NOT NULL,
            mobile_number TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

_init_users_db()

def _hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

@api_view(['POST'])
def register_user(request):
    """Register User Endpoint — POST {username, phone_number (optional), password, confirm_password}"""
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")
    confirm_password = request.data.get("confirm_password", "")

    # Optional fields – agar frontend bhejta hai to le lo, nahi to empty
    first_name = request.data.get("first_name", "").strip()
    last_name = request.data.get("last_name", "").strip()
    middle_name = request.data.get("middle_name", "").strip()
    
    # Phone number – accept "phone_number" ya "mobile_number"
    mobile_number = request.data.get("phone_number") or request.data.get("mobile_number", "")
    mobile_number = mobile_number.strip()

    # Basic validation
    if not username or not password or not confirm_password:
        return Response({"status": "error", "message": "Username, password, and confirm password are required."}, status=400)

    if password != confirm_password:
        return Response({"status": "error", "message": "Passwords do not match."}, status=400)

    # If no first name or last name, we can set defaults ya error de sakte hain.
    # Yahan main blank allow kar raha hoon.
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        hashed = _hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, first_name, middle_name, last_name, mobile_number, password) VALUES (?, ?, ?, ?, ?, ?)",
            (username, first_name or "", middle_name or "", last_name or "", mobile_number or "", hashed)
        )
        conn.commit()
        return Response({"status": "success", "message": "Account created successfully!"})
    except sqlite3.IntegrityError:
        return Response({"status": "error", "message": "Username already exists."}, status=400)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=500)
    finally:
        conn.close()

@api_view(['POST'])
def login_user(request):
    """Login User Endpoint with Brute Force Protection — POST {username, password}"""
    username = request.data.get("username", "").strip()
    password = request.data.get("password", "")
    ip = _get_client_ip(request)

    if not username or not password:
        return Response({"status": "error", "message": "Username and password are required."}, status=400)

    # 1. Check if IP is currently banned
    with _bf_lock:
        _expire_bans()
        if ip in _banned_ips:
            info = _banned_ips[ip]
            elapsed = time.time() - info["banned_at"]
            remaining = max(0, int(BAN_DURATION_SEC - elapsed)) if BAN_DURATION_SEC > 0 else "permanent"
            return Response({
                "status": "blocked",
                "message": f"IP {ip} is banned due to too many failed attempts. Try again in {remaining}s."
            }, status=403)

    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        hashed = _hash_password(password)
        cursor.execute("SELECT id, first_name, last_name FROM users WHERE username = ? AND password = ?", (username, hashed))
        user = cursor.fetchone()
        
        if user:
            # Login successful -> Reset failed attempts for this IP
            with _bf_lock:
                _attempt_log.pop(ip, None)
            return Response({
                "status": "success", 
                "message": "Login successful!",
                "user": {
                    "id": user[0],
                    "first_name": user[1],
                    "last_name": user[2],
                    "username": username
                }
            })
        else:
            # Invalid credentials -> Record failed attempt
            with _bf_lock:
                now = time.time()
                _attempt_log.setdefault(ip, []).append(now)
                _clean_old_attempts(ip)
                count = len(_attempt_log[ip])

                if count >= MAX_ATTEMPTS:
                    # BAN the IP
                    _banned_ips[ip] = {
                        "banned_at": now,
                        "attempts": count,
                        "username": username,
                        "reason": f"Failed login attempts",
                    }
                    return Response({
                        "status": "blocked",
                        "message": f"IP {ip} has been BANNED due to {MAX_ATTEMPTS} failed login attempts. Contact admin."
                    }, status=403)
                else:
                    remaining = MAX_ATTEMPTS - count
                    return Response({
                        "status": "error",
                        "message": f"Incorrect credentials. {remaining} attempt(s) remaining before IP ban."
                    }, status=401)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=500)
    finally:
        conn.close()
