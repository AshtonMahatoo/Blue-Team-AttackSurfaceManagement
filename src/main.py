#!/usr/bin/env python3
"""
Attack Surface Management Platform - Main Entry Point
"""
import asyncio
import logging
import signal
import sys
from pathlib import Path

from src.core.asset_discovery import AssetDiscovery
from src.core.vulnerability_scanner import VulnerabilityScanner
from src.graylog_integration.graylog_client import GraylogClient
from src.utils.config_loader import ConfigLoader
from src.utils.logger import setup_logging
from src.utils.db_handler import DatabaseHandler

class ASMPlatform:
    def __init__(self, config_path="config/asm_config.yaml"):
        """Initialize ASM Platform"""
        self.config = ConfigLoader.load_config(config_path)
        self.logger = setup_logging(self.config['logging'])
        self.db = DatabaseHandler(self.config['database'])
        self.graylog = GraylogClient(self.config['graylog'])
        
        # Initialize modules
        self.asset_discovery = AssetDiscovery(self.config, self.graylog)
        self.vuln_scanner = VulnerabilityScanner(self.config, self.graylog)
        
        self.running = False
        
    async def start(self):
        """Start the ASM platform"""
        self.logger.info("Starting Attack Surface Management Platform")
        self.running = True
        
        # Connect to Graylog
        if not self.graylog.test_connection():
            self.logger.error("Cannot connect to Graylog. Exiting.")
            return False
            
        # Initialize database
        self.db.initialize()
        
        # Start scheduled tasks
        asyncio.create_task(self.scheduled_discovery())
        asyncio.create_task(self.scheduled_scanning())
        
        self.logger.info("ASM Platform started successfully")
        return True
        
    async def scheduled_discovery(self):
        """Run scheduled asset discovery"""
        while self.running:
            try:
                self.logger.info("Running asset discovery...")
                assets = await self.asset_discovery.discover()
                
                # Store in database
                self.db.store_assets(assets)
                
                # Send to Graylog
                self.graylog.send_assets(assets)
                
                self.logger.info(f"Discovered {len(assets)} assets")
                
            except Exception as e:
                self.logger.error(f"Asset discovery failed: {e}")
                
            await asyncio.sleep(self.config['discovery']['interval'])
            
    async def scheduled_scanning(self):
        """Run scheduled vulnerability scanning"""
        while self.running:
            try:
                # Get assets to scan
                assets = self.db.get_assets_to_scan()
                
                if assets:
                    self.logger.info(f"Scanning {len(assets)} assets for vulnerabilities")
                    
                    for asset in assets:
                        vulnerabilities = await self.vuln_scanner.scan(asset)
                        
                        if vulnerabilities:
                            self.db.store_vulnerabilities(vulnerabilities)
                            self.graylog.send_vulnerabilities(vulnerabilities)
                            self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities on {asset['ip']}")
                            
            except Exception as e:
                self.logger.error(f"Vulnerability scanning failed: {e}")
                
            await asyncio.sleep(self.config['scanning']['interval'])
            
    def stop(self):
        """Stop the ASM platform"""
        self.logger.info("Stopping ASM Platform")
        self.running = False
        self.db.close()
        self.logger.info("ASM Platform stopped")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Attack Surface Management Platform")
    parser.add_argument("--config", default="config/asm_config.yaml", help="Configuration file path")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    parser.add_argument("--discover", action="store_true", help="Run discovery once")
    parser.add_argument("--scan", help="Scan specific target")
    
    args = parser.parse_args()
    
    # Initialize platform
    platform = ASMPlatform(args.config)
    
    # Handle signals
    def signal_handler(sig, frame):
        platform.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run based on arguments
    if args.discover:
        # One-time discovery
        assets = asyncio.run(platform.asset_discovery.discover())
        print(f"Discovered {len(assets)} assets")
        
    elif args.scan:
        # Scan specific target
        asset = {"ip": args.scan, "type": "manual"}
        vulnerabilities = asyncio.run(platform.vuln_scanner.scan(asset))
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        
    elif args.daemon:
        # Run as daemon
        asyncio.run(platform.start())
        
        # Keep running
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            platform.stop()
            
    else:
        # Interactive mode
        asyncio.run(platform.start())

if __name__ == "__main__":
    main()