# api/admin_views.py
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render, redirect
from .views import (
    _banned_ips,
    _attempt_log,
    _bf_lock,
    SUSPICIOUS_THRESHOLD,
    MAX_ATTEMPTS,
    BAN_DURATION_SEC,
)
import time

def get_banned_list():
    """Return list of banned IPs from the shared dictionary"""
    banned_list = []
    for ip, info in _banned_ips.items():
        elapsed = int(time.time() - info["banned_at"])
        remaining = max(0, BAN_DURATION_SEC - elapsed) if BAN_DURATION_SEC > 0 else "permanent"
        banned_list.append({
            "ip":            ip,
            "banned_at":     info.get("banned_at", ""),
            "attempts":      info["attempts"],
            "last_username": info.get("username", "unknown"),
            "remaining_sec": remaining,
        })
    return banned_list

@staff_member_required
def brute_force_monitor_view(request):
    with _bf_lock:
        banned_list = get_banned_list()
        suspicious = []
        for ip, attempts in _attempt_log.items():
            if ip not in _banned_ips and len(attempts) >= SUSPICIOUS_THRESHOLD:
                suspicious.append({
                    "ip": ip,
                    "failed_attempts": len(attempts),
                    "threshold": SUSPICIOUS_THRESHOLD,
                    "status": "WARNING" if len(attempts) < MAX_ATTEMPTS else "CRITICAL"
                })

    return render(request, 'admin/brute_force_monitor.html', {
        'banned_list': banned_list,
        'suspicious_list': suspicious,
        'max_attempts': MAX_ATTEMPTS,
        'ban_duration': BAN_DURATION_SEC
    })

@staff_member_required
def unban_ip_view(request):
    if request.method == 'POST':
        ip = request.POST.get('ip')
        with _bf_lock:
            if ip in _banned_ips:
                del _banned_ips[ip]
                if ip in _attempt_log:
                    del _attempt_log[ip]
    return redirect('admin_brute_force')
