"""
Asset Discovery Module
Discovers internet-facing assets using multiple techniques
"""

import asyncio
import logging
import ipaddress
from typing import Dict, List, Set, Optional
from concurrent.futures import ThreadPoolExecutor

import nmap
import shodan
import dns.resolver
import whois
from bs4 import BeautifulSoup
import aiohttp

from src.utils.network_utils import NetworkUtils

class AssetDiscovery:
    """Discovers and catalogs external-facing assets"""
    
    def __init__(self, config: Dict, db, graylog):
        self.config = config
        self.db = db
        self.graylog = graylog
        self.logger = logging.getLogger(__name__)
        
        # Initialize scanners
        self.nmap_scanner = nmap.PortScanner() if config['scanners'].get('nmap_enabled', True) else None
        
        # Initialize Shodan
        shodan_key = config.get('shodan', {}).get('api_key')
        self.shodan_client = shodan.Shodan(shodan_key) if shodan_key else None
        
        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    async def discover(self) -> List[Dict]:
        """Main discovery method - orchestrates all discovery techniques"""
        self.logger.info("Starting asset discovery")
        
        discovered_assets = set()
        
        # Run discovery methods in parallel
        discovery_tasks = []
        
        if self.config['discovery'].get('dns_enabled', True):
            discovery_tasks.append(self.discover_via_dns())
        
        if self.config['discovery'].get('shodan_enabled', True) and self.shodan_client:
            discovery_tasks.append(self.discover_via_shodan())
        
        if self.config['discovery'].get('nmap_enabled', True):
            discovery_tasks.append(self.discover_via_nmap())
        
        if self.config['discovery'].get('certificate_enabled', True):
            discovery_tasks.append(self.discover_via_certificates())
        
        # Run all discovery methods
        results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        # Combine results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Discovery method failed: {result}")
                continue
            
            for asset in result:
                discovered_assets.add(self._normalize_asset(asset))
        
        # Convert to list and enrich with metadata
        assets = []
        for asset in discovered_assets:
            enriched_asset = await self.enrich_asset(asset)
            assets.append(enriched_asset)
        
        self.logger.info(f"Discovered {len(assets)} unique assets")
        return list(assets)
    
    async def discover_via_dns(self) -> List[Dict]:
        """Discover assets via DNS enumeration"""
        self.logger.info("Starting DNS-based discovery")
        
        assets = []
        domains = self.config['discovery'].get('domains', [])
        
        for domain in domains:
            try:
                # Discover subdomains
                subdomains = await self.enumerate_subdomains(domain)
                
                for subdomain in subdomains:
                    # Resolve to IP
                    ip_addresses = await self.resolve_dns(subdomain)
                    
                    for ip in ip_addresses:
                        asset = {
                            'type': 'dns',
                            'domain': subdomain,
                            'ip': ip,
                            'source': 'dns_enumeration',
                            'discovery_time': self._current_timestamp()
                        }
                        assets.append(asset)
                        
            except Exception as e:
                self.logger.error(f"DNS discovery failed for {domain}: {e}")
        
        return assets
    
    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple techniques"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subs = ['www', 'mail', 'ftp', 'blog', 'api', 'dev', 'test', 
                      'staging', 'admin', 'portal', 'secure', 'vpn']
        
        # Try common subdomains
        for sub in common_subs:
            subdomains.add(f"{sub}.{domain}")
        
        # Try DNS brute force
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for server in answers:
                subdomains.add(str(server).rstrip('.'))
        except:
            pass
        
        # Try certificate transparency logs (simplified)
        # In production, use certstream or crt.sh API
        
        return list(subdomains)
    
    async def discover_via_shodan(self) -> List[Dict]:
        """Discover assets using Shodan"""
        self.logger.info("Starting Shodan-based discovery")
        
        assets = []
        search_queries = self.config['discovery'].get('shodan_queries', ['org:"Company Name"'])
        
        for query in search_queries:
            try:
                # Search Shodan
                results = self.shodan_client.search(query)
                
                for result in results['matches']:
                    asset = {
                        'type': 'shodan',
                        'ip': result['ip_str'],
                        'port': result['port'],
                        'service': result.get('product', 'unknown'),
                        'banner': result.get('data', '')[:500],  # Limit banner size
                        'org': result.get('org', ''),
                        'location': result.get('location', {}),
                        'source': 'shodan',
                        'discovery_time': self._current_timestamp()
                    }
                    assets.append(asset)
                    
            except Exception as e:
                self.logger.error(f"Shodan search failed for query '{query}': {e}")
        
        return assets
    
    async def discover_via_nmap(self) -> List[Dict]:
        """Discover assets using Nmap"""
        self.logger.info("Starting Nmap-based discovery")
        
        assets = []
        target_ranges = self.config['discovery'].get('ip_ranges', [])
        
        for target_range in target_ranges:
            try:
                # Validate IP range
                if not NetworkUtils.validate_ip_range(target_range):
                    self.logger.warning(f"Invalid IP range: {target_range}")
                    continue
                
                # Run Nmap ping scan
                self.logger.debug(f"Scanning range: {target_range}")
                
                # Use async wrapper for Nmap
                scan_result = await self._async_nmap_scan(target_range)
                
                for host in scan_result.all_hosts():
                    if scan_result[host].state() == 'up':
                        asset = {
                            'type': 'nmap',
                            'ip': host,
                            'status': 'up',
                            'hostname': scan_result[host].hostname() or '',
                            'source': 'nmap_ping_scan',
                            'discovery_time': self._current_timestamp()
                        }
                        
                        # Add open ports if available
                        if 'tcp' in scan_result[host]:
                            open_ports = []
                            for port in scan_result[host]['tcp']:
                                if scan_result[host]['tcp'][port]['state'] == 'open':
                                    port_info = {
                                        'port': port,
                                        'service': scan_result[host]['tcp'][port]['name'],
                                        'version': scan_result[host]['tcp'][port].get('version', '')
                                    }
                                    open_ports.append(port_info)
                            
                            asset['open_ports'] = open_ports
                        
                        assets.append(asset)
                        
            except Exception as e:
                self.logger.error(f"Nmap scan failed for {target_range}: {e}")
        
        return assets
    
    async def _async_nmap_scan(self, target: str) -> nmap.PortScanner:
        """Run Nmap scan asynchronously"""
        loop = asyncio.get_event_loop()
        
        # Define scan arguments
        arguments = '-sn -n --max-retries 1 --host-timeout 30s'
        
        # Run in thread pool
        result = await loop.run_in_executor(
            self.executor,
            lambda: self.nmap_scanner.scan(hosts=target, arguments=arguments)
        )
        
        return result
    
    async def discover_via_certificates(self) -> List[Dict]:
        """Discover assets via SSL certificate analysis"""
        self.logger.info("Starting certificate-based discovery")
        
        assets = []
        domains = self.config['discovery'].get('domains', [])
        
        for domain in domains:
            try:
                # Get certificate information
                cert_info = await self.get_certificate_info(domain)
                
                if cert_info and 'subjectAltName' in cert_info:
                    # Extract alternative names
                    for alt_name in cert_info['subjectAltName']:
                        if alt_name.startswith('DNS:'):
                            subdomain = alt_name[4:]  # Remove 'DNS:' prefix
                            
                            # Resolve to IP
                            ip_addresses = await self.resolve_dns(subdomain)
                            
                            for ip in ip_addresses:
                                asset = {
                                    'type': 'certificate',
                                    'domain': subdomain,
                                    'ip': ip,
                                    'certificate_issuer': cert_info.get('issuer', ''),
                                    'certificate_expiry': cert_info.get('notAfter', ''),
                                    'source': 'certificate_analysis',
                                    'discovery_time': self._current_timestamp()
                                }
                                assets.append(asset)
                                
            except Exception as e:
                self.logger.error(f"Certificate discovery failed for {domain}: {e}")
        
        return assets
    
    async def get_certificate_info(self, domain: str) -> Optional[Dict]:
        """Get SSL certificate information"""
        import ssl
        import socket
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return cert
        except Exception:
            return None
    
    async def resolve_dns(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                self.executor,
                lambda: dns.resolver.resolve(hostname, 'A')
            )
            return [str(rdata) for rdata in answers]
        except Exception:
            return []
    
    async def enrich_asset(self, asset: Dict) -> Dict:
        """Enrich asset with additional information"""
        enriched = asset.copy()
        
        # Get WHOIS information
        if 'domain' in asset:
            try:
                whois_info = await self.get_whois_info(asset['domain'])
                enriched['whois'] = whois_info
            except Exception as e:
                self.logger.debug(f"WHOIS lookup failed for {asset['domain']}: {e}")
        
        # Get geolocation
        if 'ip' in asset:
            try:
                location = await self.get_geolocation(asset['ip'])
                enriched['geolocation'] = location
            except Exception as e:
                self.logger.debug(f"Geolocation failed for {asset['ip']}: {e}")
        
        # Classify asset
        enriched['classification'] = self.classify_asset(asset)
        
        # Calculate initial risk score
        enriched['initial_risk_score'] = self.calculate_initial_risk(asset)
        
        # Add metadata
        enriched['last_seen'] = self._current_timestamp()
        enriched['enrichment_complete'] = True
        
        return enriched
    
    async def get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for domain"""
        try:
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(
                self.executor,
                lambda: whois.whois(domain)
            )
            
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'status': w.status
            }
        except Exception:
            return {}
    
    async def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation for IP address"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip}") as response:
                    data = await response.json()
                    
                    if data['status'] == 'success':
                        return {
                            'country': data['country'],
                            'region': data['regionName'],
                            'city': data['city'],
                            'isp': data['isp'],
                            'org': data['org'],
                            'lat': data['lat'],
                            'lon': data['lon']
                        }
        except Exception:
            pass
        
        return {}
    
    def classify_asset(self, asset: Dict) -> str:
        """Classify asset type based on characteristics"""
        
        # Check for web server
        if 'open_ports' in asset:
            web_ports = {80, 443, 8080, 8443}
            asset_ports = {p['port'] for p in asset['open_ports']}
            if asset_ports & web_ports:
                return 'web_server'
        
        # Check for database
        if 'service' in asset:
            service = asset['service'].lower()
            if any(db in service for db in ['mysql', 'postgres', 'mongodb', 'redis']):
                return 'database'
        
        # Check for mail server
        if 'port' in asset and asset['port'] in {25, 587, 465}:
            return 'mail_server'
        
        # Default classification
        return 'network_device'
    
    def calculate_initial_risk(self, asset: Dict) -> float:
        """Calculate initial risk score for asset"""
        risk_score = 0.0
        
        # Base risk
        risk_score += 1.0
        
        # Open ports increase risk
        if 'open_ports' in asset:
            risk_score += len(asset['open_ports']) * 0.5
        
        # Specific high-risk ports
        high_risk_ports = {22, 23, 3389, 5900, 5432, 27017}
        if 'open_ports' in asset:
            for port_info in asset['open_ports']:
                if port_info['port'] in high_risk_ports:
                    risk_score += 2.0
        
        # External exposure increases risk
        if asset.get('type') in ['shodan', 'certificate']:
            risk_score += 3.0
        
        # Limit to 10
        return min(risk_score, 10.0)
    
    def _normalize_asset(self, asset: Dict) -> tuple:
        """Normalize asset for deduplication"""
        key_parts = []
        
        if 'ip' in asset:
            key_parts.append(f"ip:{asset['ip']}")
        
        if 'domain' in asset:
            key_parts.append(f"domain:{asset['domain']}")
        
        if 'port' in asset:
            key_parts.append(f"port:{asset['port']}")
        
        return tuple(sorted(key_parts))
    
    def _current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'   