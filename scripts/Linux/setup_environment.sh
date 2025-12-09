#!/bin/bash
# SP101 ASM - Environment Setup Script
# Sets up complete ASM platform on Linux

set -e

# Configuration
ASM_USER="asm"
ASM_GROUP="asm"
ASM_HOME="/opt/sp101-asm"
LOG_FILE="/var/log/asm-setup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        error "Please run as root or with sudo"
    fi
}

# Update system
update_system() {
    log "Updating system packages..."
    apt-get update && apt-get upgrade -y || error "System update failed"
    success "System updated"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..."
    
    # System tools
    apt-get install -y \
        git \
        curl \
        wget \
        vim \
        htop \
        net-tools \
        dnsutils \
        whois \
        tree \
        jq \
        unzip \
        || error "Failed to install system tools"
    
    # Security tools
    apt-get install -y \
        nmap \
        masscan \
        nikto \
        sqlmap \
        hydra \
        john \
        aircrack-ng \
        || error "Failed to install security tools"
    
    # Python
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        || error "Failed to install Python"
    
    # Database
    apt-get install -y \
        postgresql \
        postgresql-contrib \
        redis-server \
        || error "Failed to install databases"
    
    # Docker
    if ! command -v docker &> /dev/null; then
        log "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh || error "Docker installation failed"
        rm get-docker.sh
    fi
    
    # Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log "Installing Docker Compose..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
    
    success "Dependencies installed"
}

# Create ASM user
create_asm_user() {
    log "Creating ASM user and group..."
    
    if ! getent group "$ASM_GROUP" > /dev/null; then
        groupadd "$ASM_GROUP" || error "Failed to create group"
    fi
    
    if ! id "$ASM_USER" > /dev/null 2>&1; then
        useradd -m -g "$ASM_GROUP" -s /bin/bash "$ASM_USER" || error "Failed to create user"
    fi
    
    success "ASM user created"
}

# Setup directories
setup_directories() {
    log "Setting up directories..."
    
    # Main directory
    mkdir -p "$ASM_HOME" || error "Failed to create ASM home"
    chown "$ASM_USER:$ASM_GROUP" "$ASM_HOME"
    
    # Log directory
    mkdir -p /var/log/asm || error "Failed to create log directory"
    chown "$ASM_USER:$ASM_GROUP" /var/log/asm
    
    # Data directories
    mkdir -p /var/lib/asm/{data,scans,reports,backups} || error "Failed to create data directories"
    chown -R "$ASM_USER:$ASM_GROUP" /var/lib/asm
    
    # Configuration directory
    mkdir -p /etc/asm || error "Failed to create config directory"
    chown "$ASM_USER:$ASM_GROUP" /etc/asm
    
    success "Directories created"
}

# Clone or create project
setup_project() {
    log "Setting up SP101 ASM project..."
    
    cd "$ASM_HOME"
    
    if [ -d "$ASM_HOME/.git" ]; then
        log "Project already exists, updating..."
        sudo -u "$ASM_USER" git pull || error "Git pull failed"
    else
        # Clone from GitHub (or use local template)
        log "Cloning SP101 ASM project..."
        sudo -u "$ASM_USER" git clone https://github.com/your-org/sp101-asm.git . || error "Git clone failed"
    fi
    
    # Create Python virtual environment
    log "Creating Python virtual environment..."
    sudo -u "$ASM_USER" python3 -m venv venv || error "Virtual environment creation failed"
    
    # Install Python dependencies
    log "Installing Python dependencies..."
    sudo -u "$ASM_USER" bash -c "source venv/bin/activate && pip install --upgrade pip" || error "Pip upgrade failed"
    sudo -u "$ASM_USER" bash -c "source venv/bin/activate && pip install -r requirements.txt" || error "Requirements installation failed"
    
    success "Project setup complete"
}

# Configure Graylog
setup_graylog() {
    log "Configuring Graylog..."
    
    # Create Graylog directories
    mkdir -p /var/lib/graylog/{data,config} || error "Failed to create Graylog directories"
    chown -R "$ASM_USER:$ASM_GROUP" /var/lib/graylog
    
    # Generate secrets
    GRAYLOG_PASSWORD_SECRET=$(openssl rand -base64 96)
    GRAYLOG_ROOT_PASSWORD_SHA2=$(echo -n "ChangeThisPassword" | sha256sum | cut -d' ' -f1)
    
    # Create Graylog configuration
    cat > /etc/asm/graylog.env << EOF
GRAYLOG_PASSWORD_SECRET=$GRAYLOG_PASSWORD_SECRET
GRAYLOG_ROOT_PASSWORD_SHA2=$GRAYLOG_ROOT_PASSWORD_SHA2
GRAYLOG_HTTP_EXTERNAL_URI=http://$(hostname -I | awk '{print $1}'):9000/
EOF
    
    chown "$ASM_USER:$ASM_GROUP" /etc/asm/graylog.env
    
    # Start Graylog with Docker Compose
    log "Starting Graylog stack..."
    cd "$ASM_HOME/deployment/docker"
    docker-compose up -d || error "Failed to start Graylog"
    
    # Wait for Graylog to be ready
    log "Waiting for Graylog to start..."
    sleep 30
    
    # Test Graylog connection
    if curl -s http://localhost:9000/api/system/ping | grep -q "pong"; then
        success "Graylog is running"
    else
        error "Graylog failed to start"
    fi
}

# Setup database
setup_database() {
    log "Setting up databases..."
    
    # PostgreSQL setup
    sudo -u postgres psql -c "CREATE USER asm_user WITH PASSWORD 'asm_password';" || error "Failed to create PostgreSQL user"
    sudo -u postgres psql -c "CREATE DATABASE asm_db OWNER asm_user;" || error "Failed to create PostgreSQL database"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE asm_db TO asm_user;" || error "Failed to grant privileges"
    
    # Redis setup
    sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf || error "Failed to configure Redis"
    systemctl restart redis || error "Failed to restart Redis"
    
    success "Databases configured"
}

# Configure firewall
configure_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw --force enable || error "Failed to enable UFW"
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'
        ufw allow 9000/tcp comment 'Graylog Web'
        ufw allow 1514/tcp comment 'Graylog Syslog'
        ufw allow 5555/tcp comment 'Graylog GELF'
        ufw allow 5432/tcp comment 'PostgreSQL'
        ufw allow 6379/tcp comment 'Redis'
        success "Firewall configured"
    else
        log "UFW not found, skipping firewall configuration"
    fi
}

# Setup systemd service
setup_systemd() {
    log "Setting up systemd service..."
    
    cat > /etc/systemd/system/asm-platform.service << EOF
[Unit]
Description=SP101 Attack Surface Management Platform
After=network.target postgresql.service redis.service docker.service
Requires=postgresql.service redis.service docker.service

[Service]
Type=simple
User=$ASM_USER
Group=$ASM_GROUP
WorkingDirectory=$ASM_HOME
Environment="PATH=$ASM_HOME/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$ASM_HOME/venv/bin/python src/main.py --daemon
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/asm /var/lib/asm

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable asm-platform.service || error "Failed to enable ASM service"
    
    success "Systemd service configured"
}

# Setup cron jobs
setup_cron() {
    log "Setting up scheduled tasks..."
    
    # Create cron directory
    mkdir -p /etc/cron.d
    
    # Daily discovery scan
    cat > /etc/cron.d/asm-daily-discovery << EOF
# Daily asset discovery - runs at 2 AM
0 2 * * * $ASM_USER cd $ASM_HOME && $ASM_HOME/venv/bin/python src/main.py --discover >> /var/log/asm/discovery.log 2>&1
EOF
    
    # Weekly vulnerability scan
    cat > /etc/cron.d/asm-weekly-scan << EOF
# Weekly vulnerability scan - runs Sunday at 3 AM
0 3 * * 0 $ASM_USER cd $ASM_HOME && $ASM_HOME/venv/bin/python src/main.py --scan all >> /var/log/asm/scan.log 2>&1
EOF
    
    # Daily report generation
    cat > /etc/cron.d/asm-daily-report << EOF
# Daily report generation - runs at 6 AM
0 6 * * * $ASM_USER cd $ASM_HOME && $ASM_HOME/venv/bin/python src/main.py --report >> /var/log/asm/report.log 2>&1
EOF
    
    # Log rotation
    cat > /etc/logrotate.d/asm << EOF
/var/log/asm/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 $ASM_USER $ASM_GROUP
    sharedscripts
    postrotate
        systemctl reload asm-platform.service > /dev/null 2>&1 || true
    endscript
}
EOF
    
    success "Scheduled tasks configured"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    # Install monitoring tools
    apt-get install -y prometheus-node-exporter || error "Failed to install monitoring tools"
    
    # Create monitoring script
    cat > /usr/local/bin/asm-monitor << 'EOF'
#!/bin/bash
# ASM Platform Monitoring Script

check_service() {
    service_name=$1
    if systemctl is-active --quiet "$service_name"; then
        echo "✓ $service_name is running"
        return 0
    else
        echo "✗ $service_name is not running"
        return 1
    fi
}

check_disk() {
    usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$usage" -gt 90 ]; then
        echo "✗ Disk usage is high: ${usage}%"
        return 1
    else
        echo "✓ Disk usage: ${usage}%"
        return 0
    fi
}

check_memory() {
    free_mem=$(free -m | awk 'NR==2 {print $4}')
    if [ "$free_mem" -lt 100 ]; then
        echo "✗ Low memory: ${free_mem}MB free"
        return 1
    else
        echo "✓ Memory: ${free_mem}MB free"
        return 0
    fi
}

echo "=== SP101 ASM Platform Status ==="
echo "Time: $(date)"
echo ""

# Check services
check_service asm-platform
check_service postgresql
check_service redis
check_service docker

echo ""
# Check system resources
check_disk
check_memory

echo ""
# Check Graylog
if curl -s http://localhost:9000/api/system/ping | grep -q "pong"; then
    echo "✓ Graylog is accessible"
else
    echo "✗ Graylog is not accessible"
fi
EOF
    
    chmod +x /usr/local/bin/asm-monitor
    chown "$ASM_USER:$ASM_GROUP" /usr/local/bin/asm-monitor
    
    # Add to sudoers for monitoring
    echo "$ASM_USER ALL=(ALL) NOPASSWD: /usr/local/bin/asm-monitor" > /etc/sudoers.d/asm-monitor
    
    success "Monitoring configured"
}

# Main execution
main() {
    log "Starting SP101 ASM Platform Setup"
    log "================================="
    
    # Run setup steps
    check_root
    update_system
    install_dependencies
    create_asm_user
    setup_directories
    setup_project
    setup_database
    setup_graylog
    configure_firewall
    setup_systemd
    setup_cron
    setup_monitoring
    
    # Start the service
    log "Starting ASM Platform..."
    systemctl start asm-platform.service || error "Failed to start ASM service"
    
    log ""
    log "================================="
    success "SP101 ASM Platform Setup Complete!"
    log "================================="
    log ""
    log "Access Information:"
    log "  Graylog Web Interface: http://$(hostname -I | awk '{print $1}'):9000"
    log "  Graylog Username: admin"
    log "  Graylog Password: ChangeThisPassword"
    log ""
    log "  ASM Service Status: systemctl status asm-platform"
    log "  ASM Logs: journalctl -u asm-platform -f"
    log "  ASM Monitoring: asm-monitor"
    log ""
    log "Next Steps:"
    log "  1. Change default passwords"
    log "  2. Configure targets in /etc/asm/config.yaml"
    log "  3. Review and adjust scan schedules"
    log "  4. Set up alert notifications"
    log ""
    log "Setup log: $LOG_FILE"
    log "================================="
}

# Run main function
main "$@"