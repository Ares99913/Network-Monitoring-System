# Network Monitoring System

A full-stack Network Monitoring System designed to provide real-time visibility into network infrastructure, connected devices, system resources, and security events through a centralized monitoring dashboard.

The project consists of a web-based frontend developed using HTML, CSS, JavaScript, and Bootstrap, along with a Python-powered backend built on Django REST Framework. The system integrates network monitoring tools such as Scapy and Python-Nmap to collect, process, and visualize monitoring data.

---

# System Architecture

```text
Frontend (Windows)
│
├── HTML5
├── CSS3
├── JavaScript
├── Bootstrap 5
└── Chart.js
        │
        ▼
REST API Communication
        │
        ▼
Backend (Kali Linux)
│
├── Django
├── Django REST Framework
├── Scapy
├── Python-Nmap
├── Psutil
└── SQLite
```

---

# Features

## Dashboard

* Real-time monitoring overview
* System statistics
* Network activity visualization
* Alert summaries
* Performance metrics

## Network Monitoring

* Network Status Monitoring
* Traffic Analysis
* Interface Monitoring
* Connectivity Tracking
* Network Statistics Collection

## Device Monitoring

* Connected Device Discovery
* MAC Address Detection
* IP Address Identification
* Device Enumeration
* Network Asset Visibility

## System Monitoring

* CPU Usage Monitoring
* Memory Utilization Monitoring
* Disk Usage Monitoring
* Resource Tracking
* Performance Statistics

## Alert Management

* Security Alert Generation
* Event Logging
* Alert Tracking
* Monitoring Notifications

## Authentication & Access Control

* User Registration
* User Authentication
* Secure Login System
* Administrative Controls

## Brute Force Protection

* Brute Force Monitoring
* Security Status Tracking
* Attack Detection
* Administrative IP Management

---

# Technology Stack

## Frontend

* HTML5
* CSS3
* JavaScript
* Bootstrap 5
* Bootstrap Icons
* Chart.js

## Backend

* Python
* Django
* Django REST Framework

## Networking & Security

* Scapy
* Python-Nmap

## System Monitoring

* Psutil

## Database

* SQLite

---

# Project Structure

```text
Network-Monitoring-System/
│
├── NetworkMonitor-Frontend/
│   ├── css/
│   ├── js/
│   ├── dashboard.html
│   ├── NetworkMonitoring.html
│   ├── DeviceMonitoring.html
│   ├── SystemMonitoring.html
│   ├── AlertManagement.html
│   ├── loginpage.html
│   └── CreateAcc.html
│
├── backend/
│   ├── system-monitoring/
│   ├── network-monitoring/
│   ├── device-monitoring/
│   ├── alert-management/
│   ├── database/
│   ├── core/
│   ├── api/
│   ├── requirements.txt
│   └── manage.py
│
└── README.md
```

---

# REST API Endpoints

## Monitoring APIs

```http
GET /api/system-status/
GET /api/network-status/
GET /api/alert-status/
GET /api/device-scan/
GET /api/brute-force/status/
```

## Authentication APIs

```http
POST /api/auth/register/
POST /api/auth/login/
```

## Administrative APIs

```http
/admin/
POST /admin/brute-force/
```

---

# Frontend Overview

The frontend provides an interactive dashboard for monitoring network and system activities.

### Pages

* Dashboard
* Network Monitoring
* Device Monitoring
* System Monitoring
* Alert Management
* Login Page
* Account Registration

### Frontend Technologies

* HTML5
* CSS3
* JavaScript
* Bootstrap 5
* Chart.js

---

# Backend Overview

The backend is responsible for data collection, processing, monitoring operations, and API communication.

### Core Modules

* System Monitoring
* Network Monitoring
* Device Discovery
* Alert Management
* Authentication Services
* Brute Force Protection

### Backend Technologies

* Python
* Django
* Django REST Framework
* Scapy
* Python-Nmap
* Psutil
* SQLite

---

# Installation & Setup

## Clone Repository

```bash
git clone https://github.com/Ares99913/Network-Monitoring-System.git
```

## Backend Setup

```bash
cd backend

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

python3 manage.py runserver 0.0.0.0:8000
```

## Frontend Setup

Open:

```text
NetworkMonitor-Frontend/loginpage.html
```

in your preferred web browser.

---

# Development Environment

## Frontend Development

* Windows
* HTML5
* CSS3
* JavaScript
* Bootstrap 5

## Backend Development

* Kali Linux
* Python 3
* Django REST Framework
* SQLite

---

# Future Enhancements

* ARP Spoofing Detection
* Intrusion Detection System (IDS)
* USB Device Monitoring
* Advanced Threat Detection
* Security Analytics Dashboard
* Traffic Visualization
* Automated Security Response
