# Attack Surface Management Platform

Enterprise-grade Attack Surface Management platform with Graylog integration for centralized logging, monitoring, and threat intelligence.

## Features

- **Asset Discovery**: Automated discovery of internet-facing assets
- **Vulnerability Scanning**: Integrated Nmap and custom scanning
- **Graylog Integration**: Centralized logging and dashboards
- **Risk Assessment**: CVSS-based risk scoring
- **Alerting**: Email and Slack notifications
- **API**: REST API for integration with other tools

## Quick Start

### Prerequisites
- Linux (Ubuntu 20.04+ recommended)
- Docker & Docker Compose
- Python 3.11+
- 8GB RAM minimum, 16GB recommended

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/attack-surface-management.git
   cd attack-surface-management

   Run setup script:

bash
sudo bash scripts/setup_environment.sh
Configure the platform:

bash
# Edit configuration
cp .env.example .env
nano .env

cp config/asm_config.example.yaml config/asm_config.yaml
nano config/asm_config.yaml
### Start services:

bash
docker-compose up -d
Access Graylog:

URL: http://localhost:9000

Username: admin

Password: admin (change on first login)

Architecture
text
[External Scanners] → [ASM Platform] → [Graylog] → [Dashboards]
       ↓                    ↓              ↓
[Asset Database]    [Vulnerability DB] [Alerting]

## Documentation
Installation Guide

Graylog Setup

API Documentation

User Guide