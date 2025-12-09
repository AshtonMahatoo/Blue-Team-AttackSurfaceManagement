#!/bin/bash
# SP101 ASM - Quick Test Script
# Tests basic functionality of the ASM platform

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}=== SP101 ASM Quick Test ===${NC}"
echo ""

# Test 1: Check Python installation
echo -n "Test 1: Python version... "
python3 --version
if [ $? -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 2: Check virtual environment
echo -n "Test 2: Virtual environment... "
if [ -d "venv" ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 3: Check dependencies
echo -n "Test 3: Python dependencies... "
source venv/bin/activate
python3 -c "import nmap, shodan, requests, yaml, sqlalchemy" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 4: Check configuration
echo -n "Test 4: Configuration files... "
if [ -f "config/asm_config.yaml" ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 5: Run discovery test
echo -n "Test 5: Asset discovery test... "
python3 -c "
from src.core.asset_discovery import AssetDiscovery
import yaml

with open('config/asm_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Create mock database and graylog
class MockDB:
    async def store_assets(self, assets):
        pass

class MockGraylog:
    async def send_assets(self, assets):
        pass

discovery = AssetDiscovery(config, MockDB(), MockGraylog())
print(f'Discovery module loaded: {discovery.__class__.__name__}')
" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 6: Check network tools
echo -n "Test 6: Network tools... "
tools=("nmap" "whois" "dig" "nslookup")
all_found=true
for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        all_found=false
        break
    fi
done

if $all_found; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 7: Check Docker
echo -n "Test 7: Docker installation... "
if command -v docker &> /dev/null; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

# Test 8: Check services
echo -n "Test 8: Essential services... "
services_running=true
for service in postgresql redis docker; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        continue
    elif docker ps &> /dev/null; then
        continue
    else
        services_running=false
        break
    fi
done

if $services_running; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
fi

echo ""
echo -e "${YELLOW}=== Test Summary ===${NC}"
echo "All tests completed. Check results above."
echo ""
echo "To run the platform:"
echo "  source venv/bin/activate"
echo "  python src/main.py --daemon"
echo ""
echo "For interactive mode:"
echo "  python src/main.py"