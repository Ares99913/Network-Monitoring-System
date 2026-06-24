import os
import time
import datetime
import threading
import subprocess

GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
DIM     = "\033[2m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

MAX_ATTEMPTS        = 4
BAN_DURATION_SEC    = 300
MONITOR_WINDOW_SEC  = 60
SUSPICIOUS_THRESHOLD = 3
LOG_DIR             = "logs"
BRUTE_LOG           = os.path.join(LOG_DIR, "brute_force.log")
BANNED_LOG          = os.path.join(LOG_DIR, "banned_ips.log")

os.makedirs(LOG_DIR, exist_ok=True)

attempt_log: dict[str, list[float]] = {}

banned_ips: dict[str, dict] = {}

_lock = threading.Lock()

def divider(char="─", width=54, color=CYAN):
    return f"{color}{char * width}{RESET}"

def now_str():
    return datetime.datetime.now().strftime("%d-%m-%Y  %H:%M:%S")

def _write_log(filepath: str, line: str):
    with open(filepath, "a") as f:
        f.write(line + os.linesep)

def _clean_old_attempts(ip: str):

    cutoff = time.time() - MONITOR_WINDOW_SEC
    attempt_log[ip] = [t for t in attempt_log.get(ip, []) if t >= cutoff]

def _firewall_ban(ip: str):
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

def _firewall_unban(ip: str):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

def record_failed_attempt(ip: str, username: str = "unknown") -> dict:

    with _lock:
        now = time.time()

        if ip in banned_ips:
            info    = banned_ips[ip]
            elapsed = now - info["banned_at"]
            if BAN_DURATION_SEC == 0 or elapsed < BAN_DURATION_SEC:
                remaining = "∞" if BAN_DURATION_SEC == 0 else int(BAN_DURATION_SEC - elapsed)
                msg = f"IP {ip} is banned — {remaining}s remaining"
                _print_alert("CRITICAL", msg)
                return {"status": "blocked", "attempts": info["attempts"], "message": msg}
            else:
                _unban_ip_internal(ip)

        attempt_log.setdefault(ip, []).append(now)
        _clean_old_attempts(ip)
        count = len(attempt_log[ip])

        log_line = f"[ATTEMPT] {now_str()}  IP={ip}  User={username}  Count={count}/{MAX_ATTEMPTS}"
        _write_log(BRUTE_LOG, log_line)

        if count >= MAX_ATTEMPTS:
            _ban_ip(ip, username, count)
            msg = (
                f"🚫 IP {ip} BANNED after {count} failed attempts.\n"
                f"   Please contact Customer Support to unblock your access."
            )
            return {"status": "blocked", "attempts": count, "message": msg}

        elif count >= SUSPICIOUS_THRESHOLD:
            msg = (
                f"⚠️  Warning: {count} failed attempt(s) from {ip}.\n"
                f"   {MAX_ATTEMPTS - count} attempt(s) left before your IP is blocked.\n"
                f"   If this wasn't you, contact Customer Support immediately."
            )
            _print_alert("WARN", f"Suspicious activity — IP={ip}  Attempts={count}")
            return {"status": "warn", "attempts": count, "message": msg}

        else:
            msg = f"❌ Incorrect credentials. {MAX_ATTEMPTS - count} attempt(s) remaining."
            return {"status": "ok", "attempts": count, "message": msg}

def record_success(ip: str, username: str = "unknown"):

    with _lock:
        if ip in attempt_log:
            del attempt_log[ip]
        log_line = f"[SUCCESS] {now_str()}  IP={ip}  User={username}  — counter reset"
        _write_log(BRUTE_LOG, log_line)
        _print_alert("INFO", f"Successful login — IP={ip}  User={username}")

def is_banned(ip: str) -> bool:

    with _lock:
        if ip not in banned_ips:
            return False
        info    = banned_ips[ip]
        elapsed = time.time() - info["banned_at"]
        if BAN_DURATION_SEC > 0 and elapsed >= BAN_DURATION_SEC:
            _unban_ip_internal(ip)
            return False
        return True

def manual_unban(ip: str) -> bool:

    with _lock:
        if ip in banned_ips:
            _unban_ip_internal(ip)
            _print_alert("INFO", f"Manual unban — IP={ip}")
            return True
        return False

def get_banned_list() -> list[dict]:

    with _lock:
        _expire_bans()
        result = []
        for ip, info in banned_ips.items():
            elapsed   = int(time.time() - info["banned_at"])
            remaining = "∞" if BAN_DURATION_SEC == 0 else max(0, BAN_DURATION_SEC - elapsed)
            result.append({
                "ip":           ip,
                "banned_at":    datetime.datetime.fromtimestamp(info["banned_at"]).strftime("%H:%M:%S"),
                "attempts":     info["attempts"],
                "last_user":    info.get("username", "unknown"),
                "remaining_sec": remaining
            })
        return result

def _ban_ip(ip: str, username: str, attempts: int):
    banned_ips[ip] = {
        "banned_at": time.time(),
        "attempts":  attempts,
        "username":  username,
        "reason":    f"{attempts} failed login attempts in {MONITOR_WINDOW_SEC}s window"
    }
    _firewall_ban(ip)
    ban_line = (
        f"[BANNED]  {now_str()}  IP={ip}  User={username}  "
        f"Attempts={attempts}  Duration={BAN_DURATION_SEC}s"
    )
    _write_log(BRUTE_LOG,  ban_line)
    _write_log(BANNED_LOG, ban_line)
    _print_alert("CRITICAL", f"IP BANNED — {ip}  ({attempts} attempts)  User={username}")

def _unban_ip_internal(ip: str):

    banned_ips.pop(ip, None)
    attempt_log.pop(ip, None)
    _firewall_unban(ip)
    _write_log(BRUTE_LOG, f"[UNBANNED] {now_str()}  IP={ip}")

def _expire_bans():

    if BAN_DURATION_SEC == 0:
        return
    expired = [
        ip for ip, info in banned_ips.items()
        if time.time() - info["banned_at"] >= BAN_DURATION_SEC
    ]
    for ip in expired:
        _unban_ip_internal(ip)

def _print_alert(level: str, message: str):
    colors = {"CRITICAL": RED, "WARN": YELLOW, "INFO": GREEN}
    col    = colors.get(level, WHITE)
    ts     = now_str()
    print(f"  {col}{BOLD}[{level}]{RESET}  {DIM}{ts}{RESET}  {WHITE}{message}{RESET}")

def run_monitor():

    scan_count = 0
    while True:
        scan_count += 1

        with _lock:
            _expire_bans()
            active_bans    = list(banned_ips.items())
            active_suspects = {
                ip: len(ts)
                for ip, ts in attempt_log.items()
                if ip not in banned_ips and len(ts) >= SUSPICIOUS_THRESHOLD
            }

        print()
        print(divider('═', 54))
        print(f"{CYAN}{BOLD}{'   509 ARMY BASE — BRUTE FORCE MONITOR':^54}{RESET}")
        print(divider('═', 54))
        print(f"  {DIM}Scan #{scan_count:<5}  |  {now_str()}{RESET}")
        print(f"  {DIM}Policy: max {MAX_ATTEMPTS} attempts / {MONITOR_WINDOW_SEC}s  |  Ban: {BAN_DURATION_SEC}s{RESET}")

        print()
        print(f"{BOLD}  ◈ BANNED IPs  [{len(active_bans)}]{RESET}")
        if active_bans:
            print(f"  {DIM}{'IP':<18}{'User':<16}{'Attempts':<10}{'Remaining'}{RESET}")
            print(f"  {DIM}{'─'*17}  {'─'*15}  {'─'*8}  {'─'*10}{RESET}")
            for ip, info in active_bans:
                elapsed   = int(time.time() - info["banned_at"])
                remaining = "∞" if BAN_DURATION_SEC == 0 else max(0, BAN_DURATION_SEC - elapsed)
                print(
                    f"  {RED}{BOLD}{ip:<18}{RESET}"
                    f"{WHITE}{info.get('username','unknown'):<16}{RESET}"
                    f"{YELLOW}{info['attempts']:<10}{RESET}"
                    f"{DIM}{remaining}s{RESET}"
                )
        else:
            print(f"  {GREEN}{BOLD}No banned IPs{RESET}")

        print()
        print(f"{BOLD}  ◈ SUSPICIOUS ACTIVITY  [{len(active_suspects)}]{RESET}")
        if active_suspects:
            print(f"  {DIM}{'IP':<18}{'Failed Attempts (window)'}{RESET}")
            print(f"  {DIM}{'─'*17}  {'─'*22}{RESET}")
            for ip, count in active_suspects.items():
                color = RED if count >= MAX_ATTEMPTS - 1 else YELLOW
                print(f"  {color}{BOLD}{ip:<18}{RESET}{WHITE}{count} / {MAX_ATTEMPTS}{RESET}")
        else:
            print(f"  {GREEN}{BOLD}No suspicious activity{RESET}")

        print()
        print(divider('═', 54))
        print(f"  {DIM}Next refresh in 10 seconds...{RESET}")
        print(divider('─', 10))

        time.sleep(10)
