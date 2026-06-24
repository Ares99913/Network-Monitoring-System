from django.contrib import admin
from django.urls import path
from api.views import (
    get_system_status,
    get_network_status,
    get_device_scan,
    get_alert_status,
    get_brute_force_status,
    record_brute_force_attempt,
    unban_ip,
    register_user,
    login_user,
)
from api.admin_views import brute_force_monitor_view, unban_ip_view

urlpatterns = [
    # ⭐ Custom Brute Force Admin Pages (MUST be BEFORE admin.site.urls)
    path('admin/brute-force/', brute_force_monitor_view, name='admin_brute_force'),
    path('admin/brute-force/unban/', unban_ip_view, name='admin_unban_ip'),

    # Django built-in admin (only ONE time)
    path('admin/', admin.site.urls),

    # 1. System Monitoring
    path('api/system-status/', get_system_status),

    # 2. Network Monitoring
    path('api/network-status/', get_network_status),

    # 3. Device Scanning (Nmap + USB)
    path('api/device-scan/', get_device_scan),

    # 4. Alert Management
    path('api/alert-status/', get_alert_status),

    # 5. Brute Force Detection
    path('api/brute-force/status/', get_brute_force_status),
    path('api/brute-force/attempt/', record_brute_force_attempt),
    path('api/brute-force/unban/', unban_ip),

    # 6. User Authentication
    path('api/auth/register/', register_user),
    path('api/auth/login/', login_user),
]
