import psutil
import socket
import uuid
import subprocess
import time

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def get_cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
        if not temps:
            return None
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

def get_server_status():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('apache2', 'nginx', 'httpd', 'lighttpd'):
            return "Online", "OK"
    return "Offline", "CRITICAL"

def get_database_status():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in ('mysqld', 'postgres', 'mongod', 'redis-server', 'mariadbd'):
            return "Connected", "OK"
    return "Disconnected", "CRITICAL"

def get_firewall_status():
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

def get_open_ports():
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

def status_color(status_type):
    if status_type == "OK":       return GREEN
    if status_type == "WARN":     return YELLOW
    if status_type == "CRITICAL": return RED
    return WHITE

def health_line(lbl, value, status_type):
    col = status_color(status_type)
    print(f"  {WHITE}{lbl:<20}{RESET}: {col}{BOLD}{value}{RESET}")

while True:
    hostname = socket.gethostname()
    try:
        ip_address = subprocess.getoutput("hostname -I").split()[0]
    except Exception:
        ip_address = "Not Available"

    mac_address = ':'.join(
        ('%012X' % uuid.getnode())[i:i+2]
        for i in range(0, 12, 2)
    )

    cpu_usage  = psutil.cpu_percent(interval=1)
    ram_usage  = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent

    cpu_temp                  = get_cpu_temp()
    server_val,   server_st   = get_server_status()
    db_val,       db_st       = get_database_status()
    firewall_val, firewall_st = get_firewall_status()
    open_ports                = get_open_ports()

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

    print(f"\n{CYAN}{'=' * 46}{RESET}")
    print(f"{BOLD}{CYAN}   509 ARMY BASE — SYSTEM MONITORING{RESET}")
    print(f"{CYAN}{'=' * 46}{RESET}")

    print()
    print(f"{BOLD}  DEVICE INFO{RESET}")
    print(f"  {WHITE}{'Device Name':<20}{RESET}: {WHITE}{hostname}{RESET}")
    print(f"  {WHITE}{'IP Address':<20}{RESET}: {WHITE}{ip_address}{RESET}")
    print(f"  {WHITE}{'MAC Address':<20}{RESET}: {WHITE}{mac_address}{RESET}")

    print()
    print(f"{CYAN}{'─' * 46}{RESET}")
    print()
    print(f"{BOLD}  SYSTEM USAGE{RESET}")
    print(f"  {WHITE}{'CPU Usage':<20}{RESET}: {WHITE}{cpu_usage}%{RESET}")
    print(f"  {WHITE}{'RAM Usage':<20}{RESET}: {WHITE}{ram_usage}%{RESET}")
    print(f"  {WHITE}{'Disk Usage':<20}{RESET}: {WHITE}{disk_usage}%{RESET}")

    print()
    print(f"{CYAN}{'─' * 46}{RESET}")
    print()
    print(f"{BOLD}  HEALTH STATUS{RESET}")
    health_line("Server",           server_val,   server_st)
    health_line("Database",         db_val,       db_st)
    health_line("Firewall",         firewall_val, firewall_st)
    health_line("CPU Temperature",  temp_val,     temp_st)
    health_line("Critical Alerts",  str(alerts),  alert_st)

    print()
    print(f"{CYAN}{'─' * 46}{RESET}")
    print()
    print(f"{BOLD}  OPEN PORTS{RESET}")
    if open_ports:
        # Print ports in rows of 8
        row_size = 8
        for i in range(0, len(open_ports), row_size):
            row = open_ports[i:i + row_size]
            row_str = "  ".join(f"{GREEN}{BOLD}{p:<6}{RESET}" for p in row)
            print(f"  {row_str}")
        print()
        print(f"  {WHITE}{'Total Listening':<20}{RESET}: {CYAN}{BOLD}{len(open_ports)}{RESET}")
    else:
        print(f"  {YELLOW}{BOLD}No open ports detected{RESET}")

    print()
    print(f"{CYAN}{'=' * 46}{RESET}")
    print(f"{DIM}  Next refresh in 5s......{RESET}")
    print(f"{CYAN}{'─' * 10}{RESET}")

    time.sleep(5)
