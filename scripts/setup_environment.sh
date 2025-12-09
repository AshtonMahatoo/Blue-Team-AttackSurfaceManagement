#!/bin/bash
# ASM Platform Setup Script for Linux

set -e

echo "========================================="
echo "Attack Surface Management Platform Setup"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

# Update system
echo "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install Docker
echo "Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker $USER

# Install Docker Compose
echo "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install Python and dependencies
echo "Installing Python and tools..."
apt-get install -y python3 python3-pip python3-venv git nmap net-tools

# Create project directory
mkdir -p /opt/asm
cd /opt/asm

# Clone repository (or copy files)
echo "Setting up project structure..."
if [ -d "attack-surface-management" ]; then
    echo "Project already exists, updating..."
    cd attack-surface-management
    git pull
else
    git clone https://github.com/your-username/attack-surface-management.git
    cd attack-surface-management
fi

# Setup Python virtual environment
echo "Setting up Python environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p data logs config/scanners

# Copy configuration templates
if [ ! -f "config/asm_config.yaml" ]; then
    cp config/asm_config.example.yaml config/asm_config.yaml
fi

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "Please edit .env file with your configuration"
fi

# Generate Graylog secrets
echo "Generating Graylog secrets..."
GRAYLOG_PASSWORD_SECRET=$(openssl rand -base64 96)
GRAYLOG_ROOT_PASSWORD_SHA2=$(echo -n "admin" | shasum -a 256 | cut -d' ' -f1)

# Update .env file
sed -i "s/GRAYLOG_PASSWORD_SECRET=.*/GRAYLOG_PASSWORD_SECRET=$GRAYLOG_PASSWORD_SECRET/" .env
sed -i "s/GRAYLOG_ROOT_PASSWORD_SHA2=.*/GRAYLOG_ROOT_PASSWORD_SHA2=$GRAYLOG_ROOT_PASSWORD_SHA2/" .env

# Set permissions
chown -R $USER:$USER /opt/asm
chmod +x scripts/*.sh

# Setup systemd service
echo "Setting up systemd service..."
cat > /etc/systemd/system/asm-platform.service << EOF
[Unit]
Description=Attack Surface Management Platform
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/asm/attack-surface-management
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Setup monitoring cron jobs
echo "Setting up cron jobs..."
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/asm/attack-surface-management/scripts/daily_scan.sh") | crontab -
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/asm/attack-surface-management/scripts/monitoring/check_services.sh") | crontab -

# Enable and start services
systemctl daemon-reload
systemctl enable asm-platform
systemctl start asm-platform

echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo "Access Graylog at: http://$(hostname -I | awk '{print $1}'):9000"
echo "Default credentials: admin / admin"
echo ""
echo "Next steps:"
echo "1. Edit config/asm_config.yaml with your targets"
echo "2. Configure Graylog inputs and dashboards"
echo "3. Run: ./scripts/graylog/setup_graylog_inputs.sh"
echo "========================================="