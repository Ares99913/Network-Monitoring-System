# Network Monitoring System - Backend

## Overview

The backend of the Network Monitoring System is built using **Python**, **Django**, and **Django REST Framework** to provide real-time monitoring, device discovery, network analysis, security alert management, and authentication services.

The system integrates industry-standard networking and monitoring tools such as **Scapy**, **Python-Nmap**, and **Psutil** to collect and process network and system information while exposing the data through RESTful APIs for frontend integration.

---

# Key Features

## System Monitoring

* CPU Usage Monitoring
* Memory Utilization Monitoring
* Disk Usage Monitoring
* System Resource Tracking
* Performance Statistics

## Network Monitoring

* Network Interface Monitoring
* Network Status Monitoring
* Network Activity Analysis
* Network Statistics Collection
* Connectivity Monitoring

## Device Discovery

* Connected Device Detection
* IP Address Identification
* MAC Address Detection
* Device Enumeration
* Network Asset Visibility

## Alert Management

* Security Alert Generation
* Event Logging
* Alert Tracking
* Alert Status Monitoring
* Security Notifications

## Authentication & Access Control

* User Registration
* User Authentication
* Secure Login System
* Django Administration Panel

## Brute Force Protection

* Brute Force Monitoring
* Attack Detection
* Security Status Tracking
* Administrative IP Management

---

# Technology Stack

## Backend Framework

* Python
* Django
* Django REST Framework

## Network & Security Libraries

* Scapy
* Python-Nmap

## System Monitoring

* Psutil

## Database

* SQLite

## API Architecture

* REST APIs
* JSON Response Handling

---

# Project Structure

```text
backend/
│
├── system-monitoring/
│   └── monitor.py
│
├── network-monitoring/
│   └── network.py
│
├── device-monitoring/
│   └── devices.py
│
├── alert-management/
│   └── alerts.py
│
├── database/
│   └── db.sqlite3
│
├── core/
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
├── api/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── views.py
│   ├── admin_views.py
│   └── migrations/
│
├── requirements.txt
│
└── manage.py
```

---

# Core Configuration

The **core** module contains the central Django project configuration responsible for:

* Project Settings
* URL Routing
* ASGI Configuration
* WSGI Configuration
* Application Configuration

---

# API Layer

The **api** module manages all backend services and REST API operations including:

* REST API Endpoints
* Database Models
* Administrative Controls
* Authentication Services
* Monitoring APIs
* Alert Management APIs
* Brute Force Protection APIs

---

# Monitoring Modules

The monitoring components are responsible for:

* System Resource Monitoring
* Network Activity Monitoring
* Device Discovery & Detection
* Security Alert Generation
* Event Logging & Tracking

---

# Database Layer

SQLite is used for storing:

* Monitoring Records
* Security Alerts
* User Information
* System Logs
* Application Data

---

# REST API Endpoints

## System Monitoring API

```http
GET /api/system-status/
```

Provides:

* CPU Usage
* Memory Usage
* Disk Utilization
* System Statistics

---

## Network Monitoring API

```http
GET /api/network-status/
```

Provides:

* Network Information
* Interface Statistics
* Network Status
* Connectivity Information

---

## Alert Management API

```http
GET /api/alert-status/
```

Provides:

* Security Alerts
* Event Logs
* Alert Status
* Monitoring Notifications

---

## Device Discovery API

```http
GET /api/device-scan/
```

Provides:

* Connected Devices
* IP Addresses
* MAC Addresses
* Device Discovery Results

---

## Brute Force Monitoring API

```http
GET /api/brute-force/status/
```

Provides:

* Protection Status
* Monitoring Information
* Security Statistics

---

## Authentication APIs

### User Registration

```http
POST /api/auth/register/
```

### User Login

```http
POST /api/auth/login/
```

---

## Administrative Panel

```http
/admin/
```

Provides:

* User Management
* Database Administration
* Security Configuration
* Monitoring Controls

---

## Administrative Security Actions

```http
POST /admin/brute-force/
```

Used for:

* IP Release Operations
* Security Administration
* Brute Force Management

---

# Development Environment

## Backend Development

* Kali Linux
* Python 3
* Django
* Django REST Framework
* SQLite

## Frontend Integration

The backend communicates with a web-based frontend developed using:

* HTML5
* CSS3
* JavaScript
* Bootstrap 5

---

# Installation & Setup

## Clone Repository

```bash
git clone https://github.com/Ares99913/Network-Monitoring-System.git
```

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Start Django Server

```bash
python3 manage.py runserver 0.0.0.0:8000
```

---

# Dependencies

```text
Django
djangorestframework
scapy
python-nmap
psutil
```

---

# Future Enhancements

* ARP Spoofing Detection
* Intrusion Detection System (IDS)
* Advanced Threat Detection
* Automated Alert Response
* Traffic Visualization Dashboard
* Security Analytics
* USB Device Monitoring

---

