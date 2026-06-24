import datetime
import os
import psutil
import socket
import time
import uuid
import shutil
import argparse

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"

MAX_WIDTH = 80

def get_terminal_width():
    try:
        cols = shutil.get_terminal_size().columns
        return min(cols, MAX_WIDTH)
    except:
        return MAX_WIDTH

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def divider(char="─", width=None, color=CYAN):
    if width is None:
        width = get_terminal_width()
    return f"{color}{char * width}{RESET}"

def title(text, width=None):
    if width is None:
        width = get_terminal_width()
    return f"{CYAN}{BOLD}{text:^{width}}{RESET}"

def section(text):
    return f"{BOLD}  ◈ {text}{RESET}"

def label(text, width=14):
    return f"{DIM}{WHITE}{text:<{width}}{RESET}"

def value(text, color=WHITE):
    return f"{color}{BOLD}{text}{RESET}"

def status_badge(is_up):
    return f"{GREEN}{BOLD}▲ UP{RESET}" if is_up else f"{RED}{BOLD}▼ DOWN{RESET}"

def speed_color(speed_mbps):
    try:
        speed = float(speed_mbps)
    except:
        return WHITE
    if speed <= 0:
        return DIM + WHITE
    if speed >= 1000:
        return GREEN
    if speed >= 100:
        return CYAN
    return YELLOW

def bytes_to_mb(b):
    return round(b / (1024 * 1024), 2)

def bytes_to_gb(b):
    return round(b / (1024 * 1024 * 1024), 3)

def get_live_speed(prev_sent, prev_recv, prev_time):
    net = psutil.net_io_counters()
    now = time.time()
    elapsed = max(now - prev_time, 0.001)
    sent_speed = ((net.bytes_sent - prev_sent) * 8) / (elapsed * 1_000_000)
    recv_speed = ((net.bytes_recv - prev_recv) * 8) / (elapsed * 1_000_000)
    return round(sent_speed, 2), round(recv_speed, 2), net.bytes_sent, net.bytes_recv, now

def get_primary_ip():
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    return "Not Available"

def get_mac_address():
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == psutil.AF_LINK and addr.address and addr.address != "00:00:00:00:00:00":
                return addr.address
    
    if os.path.exists("/sys/class/net/"):
        for iface in os.listdir("/sys/class/net/"):
            if iface == "lo":
                continue
            mac_path = os.path.join("/sys/class/net/", iface, "address")
            if os.path.exists(mac_path):
                try:
                    with open(mac_path, "r") as f:
                        mac = f.read().strip()
                        if mac and mac != "00:00:00:00:00:00":
                            return mac
                except:
                    pass
    
    mac = uuid.getnode()
    if mac == 0 or mac & 0x010000000000:
        return "Not Available"
    return ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))

def get_iface_ip(iface, addrs):
    if iface not in addrs:
        return "—"
    for a in addrs[iface]:
        if a.family == socket.AF_INET:
            return a.address
    return "—"

def print_kv(label_text, value_text, value_color=WHITE, indent="  "):
    print(f"{indent}{label(label_text)} {value(value_text, value_color)}")

def print_iface_card(iface, stats, addrs):
    iface_ip = get_iface_ip(iface, addrs)
    up_text = status_badge(stats.isup)
    spd_color = speed_color(stats.speed)

    print()
    print(f"  {CYAN}{BOLD}{iface:<12}{RESET} {up_text}")
    print(f"    {label('IP', 12)} {value(iface_ip, WHITE)}")
    print(f"    {label('Speed', 12)} {value(f'{stats.speed} Mbps', spd_color)}")
    print(f"    {label('MTU', 12)} {value(str(stats.mtu), DIM + WHITE)}")

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interval", type=int, default=10, help="Refresh seconds")
    return parser.parse_args()

def main():
    args = parse_args()
    interval = args.interval

    _net = psutil.net_io_counters()
    prev_sent = _net.bytes_sent
    prev_recv = _net.bytes_recv
    prev_time = time.time()

    while True:
        clear_screen()
        width = get_terminal_width()

        hostname = socket.gethostname()
        ip_address = get_primary_ip()
        mac_address = get_mac_address()

        net_io = psutil.net_io_counters()
        total_sent = bytes_to_mb(net_io.bytes_sent)
        total_recv = bytes_to_mb(net_io.bytes_recv)
        total_gb = bytes_to_gb(net_io.bytes_sent + net_io.bytes_recv)
        packets_sent = net_io.packets_sent
        packets_recv = net_io.packets_recv

        up_mbps, down_mbps, prev_sent, prev_recv, prev_time = get_live_speed(
            prev_sent, prev_recv, prev_time
        )

        interfaces = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        now_str = datetime.datetime.now().strftime("%d-%m-%Y  %H:%M:%S")

        print(divider('═', width=width))
        print(title("509 ARMY BASE — NETWORK MONITORING", width=width))
        print(divider('═', width=width))
        print(f"{DIM}  Refreshed : {now_str}{RESET}")
        print()

        print(section("DEVICE IDENTITY"))
        print_kv("Hostname", hostname, CYAN)
        print_kv("IP Address", ip_address, GREEN)
        print_kv("MAC Address", mac_address, YELLOW)
        print()
        print(divider(width=width))

        print()
        print(section("LIVE THROUGHPUT"))
        print_kv("Upload", f"{up_mbps} Mbps", speed_color(up_mbps))
        print_kv("Download", f"{down_mbps} Mbps", speed_color(down_mbps))
        print()
        print(divider(width=width))

        print()
        print(section("TOTAL DATA TRANSFER"))
        print_kv("Data Sent", f"{total_sent} MB", CYAN)
        print_kv("Data Received", f"{total_recv} MB", GREEN)
        print_kv("Total Traffic", f"{total_gb} GB", WHITE)
        print()
        print(divider(width=width))

        print()
        print(section("PACKETS"))
        print_kv("Packets Sent", f"{packets_sent:,}", CYAN)
        print_kv("Packets Received", f"{packets_recv:,}", GREEN)
        print()
        print(divider(width=width))

        print()
        print(section("NETWORK INTERFACES"))
        for iface, stats in interfaces.items():
            print_iface_card(iface, stats, addrs)

        print()
        print(divider(width=width))

        print()
        print(section("ACTIVE CONNECTIONS"))
        try:
            connections = psutil.net_connections(kind="inet")
            established = [c for c in connections if c.status == "ESTABLISHED"]
            listening = [c for c in connections if c.status == "LISTEN"]
            time_wait = [c for c in connections if c.status == "TIME_WAIT"]

            print_kv("Established", str(len(established)), GREEN)
            print_kv("Listening", str(len(listening)), CYAN)
            print_kv("Time Wait", str(len(time_wait)), YELLOW)
            print_kv("Total Sockets", str(len(connections)), WHITE)

            if established:
                print()
                print(f"  {DIM}{'Remote Address':<26}{'Proto':<8}{'Port':<8}{RESET}")
                shown = 0
                seen = set()
                for c in established:
                    if not c.raddr or shown >= 5:
                        continue
                    rip = c.raddr.ip
                    rport = c.raddr.port
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    key = (rip, rport, proto)
                    if key in seen:
                        continue
                    seen.add(key)
                    print(f"  {CYAN}{rip:<26}{WHITE}{proto:<8}{GREEN}{str(rport):<8}{RESET}")
                    shown += 1
        except PermissionError:
            print(f"  {RED}Permission denied – run with sudo to see connections.{RESET}")
        except Exception as e:
            print(f"  {RED}Error: {e}{RESET}")

        print()
        print(divider('═', width=width))
        print(f"{DIM}  Next refresh in {interval}s...{RESET}")
        print(divider('═', width=min(width, 18)))
        time.sleep(interval)

if __name__ == "__main__":
    main()
