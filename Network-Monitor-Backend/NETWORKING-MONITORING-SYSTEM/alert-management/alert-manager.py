import os
import time
import datetime
import psutil
import socket
import uuid
import subprocess

GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
DIM     = "\033[2m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

LOG_DIR      = "logs"
ALERT_LOG    = os.path.join(LOG_DIR, "alerts.log")
CRITICAL_LOG = os.path.join(LOG_DIR, "critical.log")
SESSION_LOG  = os.path.join(LOG_DIR, "session.log")

os.makedirs(LOG_DIR, exist_ok=True)

cooldowns = {}

session_counts = {"INFO": 0, "WARN": 0, "CRITICAL": 0}

COOLDOWN_SECONDS = {
    "CPU_HIGH":        60,
    "RAM_HIGH":        60,
    "DISK_HIGH":       120,
    "TEMP_WARN":       60,
    "TEMP_CRITICAL":   30,
    "FIREWALL":        120,
    "SERVER_DOWN":     30,
    "DB_DOWN":         30,
    "PORT_SUSPICIOUS": 60,
    "HIGH_BANDWIDTH":  30,
    "TOO_MANY_SOCKETS":60,
}

SUSPICIOUS_PORTS = {22, 23, 3389, 4444, 5900, 6666, 7777, 8080, 9090}

def divider(char="─", width=54, color=CYAN):
    return f"{color}{char * width}{RESET}"

def now_str():
    return datetime.datetime.now().strftime("%d-%m-%Y  %H:%M:%S")

def level_color(level):
    if level == "CRITICAL": return RED
    if level == "WARN":     return YELLOW
    if level == "INFO":     return GREEN
    return WHITE

def log_alert(level, message):
    timestamp = now_str()
    line      = f"[{level}] {timestamp}  {message}"
    col       = level_color(level)

    print(f"  {col}{BOLD}[{level}]{RESET}  {DIM}{timestamp}{RESET}  {WHITE}{message}{RESET}")

    with open(ALERT_LOG, "a") as f:
        f.write(line)
        f.write(os.linesep)

    if level == "CRITICAL":
        with open(CRITICAL_LOG, "a") as f:
            f.write(line)
            f.write(os.linesep)

    session_counts[level] += 1

def can_alert(key):
    cooldown = COOLDOWN_SECONDS.get(key, 60)
    last     = cooldowns.get(key, 0)
    if time.time() - last >= cooldown:
        cooldowns[key] = time.time()
        return True
    return False

def check_system():
    alerts = []

    cpu = psutil.cpu_percent(interval=1)
    if cpu >= 90 and can_alert("CPU_HIGH"):
        alerts.append(("CRITICAL", f"CPU Usage Critical — {cpu}%"))
    elif cpu >= 75 and can_alert("CPU_HIGH"):
        alerts.append(("WARN", f"CPU Usage High — {cpu}%"))

    ram = psutil.virtual_memory().percent
    if ram >= 90 and can_alert("RAM_HIGH"):
        alerts.append(("CRITICAL", f"RAM Usage Critical — {ram}%"))
    elif ram >= 80 and can_alert("RAM_HIGH"):
        alerts.append(("WARN", f"RAM Usage High — {ram}%"))

    disk = psutil.disk_usage('/').percent
    if disk >= 95 and can_alert("DISK_HIGH"):
        alerts.append(("CRITICAL", f"Disk Usage Critical — {disk}%"))
    elif disk >= 85 and can_alert("DISK_HIGH"):
        alerts.append(("WARN", f"Disk Usage High — {disk}%"))

    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                for entry in entries:
                    if entry.current and entry.current > 0:
                        t = entry.current
                        if t >= 85 and can_alert("TEMP_CRITICAL"):
                            alerts.append(("CRITICAL", f"CPU Temp Critical — {t}°C"))
                        elif t >= 70 and can_alert("TEMP_WARN"):
                            alerts.append(("WARN", f"CPU Temp High — {t}°C"))
                        break
    except Exception:
        pass

    fw_ok = False
    try:
        out = subprocess.getoutput("ufw status")
        if "active" in out.lower():
            fw_ok = True
    except Exception:
        pass
    if not fw_ok and can_alert("FIREWALL"):
        alerts.append(("CRITICAL", "Firewall Inactive — System Unprotected"))

    server_ok = False
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('apache2', 'nginx', 'httpd', 'lighttpd'):
            server_ok = True
            break
    if not server_ok and can_alert("SERVER_DOWN"):
        alerts.append(("WARN", "Web Server Offline"))

    db_ok = False
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('mysqld', 'postgres', 'mongod', 'redis-server', 'mariadbd'):
            db_ok = True
            break
    if not db_ok and can_alert("DB_DOWN"):
        alerts.append(("WARN", "Database Disconnected"))

    try:
        conns = psutil.net_connections(kind='inet')
        listening_ports = {c.laddr.port for c in conns if c.status == 'LISTEN' and c.laddr}
        for port in listening_ports:
            if port in SUSPICIOUS_PORTS:
                key = f"PORT_{port}"
                if can_alert("PORT_SUSPICIOUS"):
                    alerts.append(("WARN", f"Suspicious Port Open — {port}"))
    except Exception:
        pass

    return alerts

def check_network():
    alerts = []

    try:
        conns  = psutil.net_connections(kind='inet')
        total  = len(conns)
        if total > 200 and can_alert("TOO_MANY_SOCKETS"):
            alerts.append(("WARN", f"Too Many Open Sockets — {total}"))

        n1 = psutil.net_io_counters()
        time.sleep(1)
        n2 = psutil.net_io_counters()
        up = round(((n2.bytes_sent - n1.bytes_sent) * 8) / 1_000_000, 2)
        dn = round(((n2.bytes_recv - n1.bytes_recv) * 8) / 1_000_000, 2)
        if (up > 100 or dn > 100) and can_alert("HIGH_BANDWIDTH"):
            alerts.append(("WARN", f"High Bandwidth — Up: {up} Mbps  Down: {dn} Mbps"))
    except Exception:
        pass

    return alerts

def print_session_summary():
    print()
    print(divider('═', 54))
    print(f"{BOLD}{CYAN}  SESSION ALERT SUMMARY{RESET}")
    print(divider('─', 54))
    print(f"  {RED}{BOLD}CRITICAL{RESET}  →  {WHITE}{BOLD}{session_counts['CRITICAL']}{RESET}")
    print(f"  {YELLOW}{BOLD}WARN    {RESET}  →  {WHITE}{BOLD}{session_counts['WARN']}{RESET}")
    print(f"  {GREEN}{BOLD}INFO    {RESET}  →  {WHITE}{BOLD}{session_counts['INFO']}{RESET}")
    print(divider('═', 54))

def write_session_log():
    with open(SESSION_LOG, "a") as f:
        f.write(os.linesep)
        f.write(f"=== Session ended: {now_str()} ===" + os.linesep)
        f.write(f"CRITICAL: {session_counts['CRITICAL']}" + os.linesep)
        f.write(f"WARN:     {session_counts['WARN']}"     + os.linesep)
        f.write(f"INFO:     {session_counts['INFO']}"     + os.linesep)

scan_count = 0

while True:
    scan_count += 1

    sys_alerts  = check_system()
    net_alerts  = check_network()
    all_alerts  = sys_alerts + net_alerts

    print()
    print(divider('═', 54))
    print(f"{CYAN}{BOLD}{'   509 ARMY BASE — ALERT MANAGER':^54}{RESET}")
    print(divider('═', 54))
    print(f"  {DIM}Scan #{scan_count:<6}  |  {now_str()}{RESET}")
    print()

    if all_alerts:
        print(f"{BOLD}  ◈ ACTIVE ALERTS{RESET}")
        for level, message in all_alerts:
            log_alert(level, message)
    else:
        print(f"  {GREEN}{BOLD}◈ ALL SYSTEMS NORMAL{RESET}")
        log_alert("INFO", "All systems normal")

    print()
    print(divider())
    print()
    print(f"{BOLD}  ◈ LIVE STATUS{RESET}")

    cpu  = psutil.cpu_percent()
    ram  = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    def stat_color(val, warn, crit):
        if val >= crit:  return RED
        if val >= warn:  return YELLOW
        return GREEN

    print(f"  {DIM}{'CPU Usage':<20}{RESET}  {stat_color(cpu,75,90)}{BOLD}{cpu}%{RESET}")
    print(f"  {DIM}{'RAM Usage':<20}{RESET}  {stat_color(ram,80,90)}{BOLD}{ram}%{RESET}")
    print(f"  {DIM}{'Disk Usage':<20}{RESET}  {stat_color(disk,85,95)}{BOLD}{disk}%{RESET}")

    print()
    print(f"  {DIM}{'Total CRITICAL':<20}{RESET}  {RED}{BOLD}{session_counts['CRITICAL']}{RESET}")
    print(f"  {DIM}{'Total WARN':<20}{RESET}  {YELLOW}{BOLD}{session_counts['WARN']}{RESET}")
    print(f"  {DIM}{'Total INFO':<20}{RESET}  {GREEN}{BOLD}{session_counts['INFO']}{RESET}")

    print()
    print(divider('═', 54))
    print(f"  {DIM}Next check in 10 seconds...{RESET}")
    print(divider('─', 10))

    if scan_count % 10 == 0:
        print_session_summary()
        write_session_log()

    time.sleep(10)
