#!/usr/bin/env python3
"""
RAVEN - Reconnaissance Analysis & Vulnerability Enumeration Network
====================================================================
Professional Reconnaissance Framework for Cybersecurity Professionals
Enhanced for Kali Linux with automated dependency management

Author: Yx0R
Purpose: Authorized security assessments and education
License: For authorized testing only

DISCLAIMER: Use only on systems you own or have explicit permission to test.
Unauthorized access is illegal and unethical.
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
from typing import List, Dict, Set, Optional, Tuple, Any
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
import csv
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')

# Initialize colorama
init(autoreset=True)

class RavenModule(Enum):
    """Enumeration of RAVEN modules"""
    DNS = "dns_recon"
    SUBDOMAINS = "subdomain_enum"
    PORTS = "port_scanning"
    TECH = "tech_stack"
    DIRS = "directory_enum"
    ENDPOINTS = "endpoint_discovery"
    DATA = "data_exposure"
    CLOUD = "cloud_config"
    WAF = "waf_detection"
    SSL = "ssl_analysis"
    EMAIL = "email_harvesting"
    NETWORK = "network_mapping"
    APIS = "api_discovery"
    VULN_PROBABILITY = "vulnerability_probability"

@dataclass
class RavenConfig:
    """Configuration for RAVEN framework"""
    target: str
    output_dir: str = "raven_results"
    threads: int = 25
    timeout: int = 30
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
    wordlist_dir: str = "/usr/share/seclists"
    modules: List[RavenModule] = field(default_factory=lambda: list(RavenModule))
    depth: int = 2  # Recon depth (1: Light, 2: Standard, 3: Aggressive)
    api_keys: Dict = field(default_factory=dict)
    proxy: Optional[str] = None
    rate_limit: int = 10
    save_intermediate: bool = True
    report_format: str = "all"  # json, html, md, pdf, all
    quiet: bool = False

class DependencyManager:
    """Manage tool and module dependencies"""
    
    @staticmethod
    def check_root():
        """Check if running as root"""
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] RAVEN requires root privileges. Run with: sudo {sys.argv[0]}{Fore.RESET}")
            sys.exit(1)
    
    @staticmethod
    def check_dependencies():
        """Check and install required dependencies"""
        required_tools = {
            'nmap': 'apt-get install nmap -y',
            'whois': 'apt-get install whois -y',
            'dnsutils': 'apt-get install dnsutils -y',
            'python3-pip': 'apt-get install python3-pip -y',
            'git': 'apt-get install git -y',
            'curl': 'apt-get install curl -y',
            'wget': 'apt-get install wget -y',
            'sslscan': 'apt-get install sslscan -y',
            'nikto': 'apt-get install nikto -y',
            'dirb': 'apt-get install dirb -y',
        }
        
        python_packages = [
            'requests', 'beautifulsoup4', 'python-whois', 'dnspython',
            'colorama', 'tldextract', 'pandas', 'pyyaml', 'xmltodict',
            'aiohttp', 'netifaces', 'nmap', 'urllib3'
        ]
        
        seclists_path = "/usr/share/seclists"
        
        print(f"{Fore.CYAN}[*] Checking system dependencies...")
        
        # Check tools
        missing_tools = []
        for tool, install_cmd in required_tools.items():
            try:
                subprocess.run(['which', tool], check=True, capture_output=True)
                print(f"{Fore.GREEN}[+] Tool found: {tool}")
            except subprocess.CalledProcessError:
                print(f"{Fore.YELLOW}[-] Missing: {tool}")
                missing_tools.append((tool, install_cmd))
        
        # Install missing tools
        if missing_tools:
            print(f"{Fore.YELLOW}[*] Installing missing tools...")
            for tool, install_cmd in missing_tools:
                try:
                    print(f"{Fore.CYAN}[*] Installing {tool}...")
                    subprocess.run(install_cmd.split(), check=True)
                    print(f"{Fore.GREEN}[+] Successfully installed {tool}")
                except subprocess.CalledProcessError:
                    print(f"{Fore.RED}[!] Failed to install {tool}")
        
        # Check Python packages
        print(f"{Fore.CYAN}[*] Checking Python packages...")
        for package in python_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"{Fore.GREEN}[+] Package found: {package}")
            except ImportError:
                print(f"{Fore.YELLOW}[-] Missing package: {package}")
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', package], check=True)
                    print(f"{Fore.GREEN}[+] Successfully installed {package}")
                except:
                    print(f"{Fore.RED}[!] Failed to install {package}")
        
        # Check SecLists
        if not os.path.exists(seclists_path):
            print(f"{Fore.YELLOW}[-] SecLists not found. Installing...")
            try:
                subprocess.run(['git', 'clone', 'https://github.com/danielmiessler/SecLists.git', seclists_path], check=True)
                print(f"{Fore.GREEN}[+] SecLists installed successfully")
            except:
                print(f"{Fore.RED}[!] Failed to install SecLists")
                print(f"{Fore.YELLOW}[*] Creating minimal wordlists...")
                DependencyManager.create_minimal_wordlists(seclists_path)
        
        print(f"{Fore.GREEN}[+] All dependencies checked{Fore.RESET}")
    
    @staticmethod
    def create_minimal_wordlists(path: str):
        """Create minimal wordlists if SecLists not available"""
        os.makedirs(path, exist_ok=True)
        
        # Subdomains
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'secure', 'portal', 'blog', 'webmail', 'ns1', 'ns2', 'cdn',
            'static', 'assets', 'app', 'beta', 'alpha', 'demo', 'shop',
            'store', 'forum', 'support', 'help', 'download', 'upload',
            'video', 'image', 'img', 'media', 'cdn', 'proxy', 'vpn',
            'remote', 'ssh', 'git', 'svn', 'jenkins', 'docker', 'kubernetes',
            'k8s', 'monitor', 'metrics', 'grafana', 'prometheus', 'elk',
            'log', 'logs', 'analytics', 'stats', 'status', 'health',
            'monitoring', 'alert', 'alerts', 'backup', 'backups', 'archive'
        ]
        
        # Directories
        directories = [
            'admin', 'administrator', 'login', 'logout', 'signin', 'signout',
            'register', 'signup', 'dashboard', 'panel', 'control', 'manager',
            'wp-admin', 'wp-login', 'administrator', 'user', 'users', 'account',
            'accounts', 'profile', 'profiles', 'settings', 'config', 'configuration',
            'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'rest/v1', 'graphql',
            'soap', 'xmlrpc', 'jsonrpc', 'oauth', 'auth', 'authorize', 'token',
            'backend', 'backoffice', 'cms', 'content', 'uploads', 'files',
            'images', 'img', 'media', 'assets', 'static', 'public', 'private',
            'secure', 'protected', 'hidden', 'secret', 'confidential',
            'backup', 'backups', 'archive', 'archives', 'old', 'temp', 'tmp',
            'cache', 'cached', 'log', 'logs', 'debug', 'testing', 'test',
            'dev', 'development', 'staging', 'beta', 'alpha', 'demo'
        ]
        
        # Files
        files = [
            'robots.txt', 'sitemap.xml', 'sitemap_index.xml', 'crossdomain.xml',
            'clientaccesspolicy.xml', '.htaccess', '.htpasswd', 'web.config',
            'phpinfo.php', 'test.php', 'info.php', 'admin.php', 'config.php',
            'settings.php', 'database.php', 'db.php', 'sql.php', 'backup.sql',
            'dump.sql', 'database.sql', 'backup.tar', 'backup.tar.gz',
            'backup.zip', 'www.zip', 'site.tar.gz', 'backup.rar',
            '.git/HEAD', '.git/config', '.svn/entries', '.env', '.env.example',
            '.env.local', '.env.production', '.env.development',
            'config.json', 'config.yml', 'config.yaml', 'settings.json',
            'settings.yml', 'settings.yaml', 'secrets.json', 'secrets.yml',
            'secrets.yaml', 'credentials.json', 'credentials.yml',
            'docker-compose.yml', 'docker-compose.yaml', 'dockerfile',
            'dockerfile.prod', 'jenkinsfile', 'travis.yml', '.travis.yml',
            'circle.yml', '.circleci/config.yml', 'azure-pipelines.yml',
            '.github/workflows/ci.yml', 'bitbucket-pipelines.yml'
        ]
        
        # API endpoints
        api_endpoints = [
            'users', 'user', 'accounts', 'account', 'profiles', 'profile',
            'products', 'product', 'items', 'item', 'orders', 'order',
            'payments', 'payment', 'transactions', 'transaction',
            'invoices', 'invoice', 'customers', 'customer', 'clients',
            'client', 'employees', 'employee', 'staff', 'members', 'member',
            'posts', 'post', 'articles', 'article', 'blogs', 'blog',
            'comments', 'comment', 'reviews', 'review', 'ratings', 'rating',
            'categories', 'category', 'tags', 'tag', 'search', 'filter',
            'auth', 'authenticate', 'login', 'logout', 'register', 'signup',
            'token', 'refresh', 'verify', 'validate', 'password', 'reset',
            'forgot', 'change', 'update', 'delete', 'remove', 'create',
            'new', 'edit', 'modify', 'upload', 'download', 'export',
            'import', 'sync', 'webhook', 'callback', 'notify', 'notification'
        ]
        
        # Create directories
        os.makedirs(os.path.join(path, "Discovery", "DNS"), exist_ok=True)
        os.makedirs(os.path.join(path, "Discovery", "Web-Content"), exist_ok=True)
        os.makedirs(os.path.join(path, "Discovery", "Web-Content", "API"), exist_ok=True)
        
        # Write wordlists
        with open(os.path.join(path, "Discovery", "DNS", "subdomains.txt"), 'w') as f:
            f.write('\n'.join(subdomains))
        
        with open(os.path.join(path, "Discovery", "Web-Content", "common.txt"), 'w') as f:
            f.write('\n'.join(directories))
        
        with open(os.path.join(path, "Discovery", "Web-Content", "files.txt"), 'w') as f:
            f.write('\n'.join(files))
        
        with open(os.path.join(path, "Discovery", "Web-Content", "API", "endpoints.txt"), 'w') as f:
            f.write('\n'.join(api_endpoints))
        
        print(f"{Fore.GREEN}[+] Created minimal wordlists at {path}")

class RavenFramework:
    """
    RAVEN - Professional Reconnaissance Framework
    """
    
    def __init__(self, config: RavenConfig):
        """Initialize the framework with configuration"""
        self.config = config
        self.target = self._normalize_target(config.target)
        self.domain = self._extract_domain(self.target)
        self.base_domain = self._extract_base_domain(self.domain)
        
        # Setup logging
        self._setup_logging()
        
        # Create output directories
        self._setup_directories()
        
        # Initialize results storage
        self.results = self._init_results_structure()
        
        # Load wordlists
        self.wordlists = self._load_wordlists()
        
        # Initialize tools
        self.nm = nmap.PortScanner() if self._check_tool('nmap') else None
        
        # Set up session
        self.session = self._create_session()
        
        # Statistics
        self.stats = {
            'start_time': time.time(),
            'requests_made': 0,
            'subdomains_found': 0,
            'data_exposed': 0,
            'vulnerability_hints': 0
        }
        
        logger.info(f"{Fore.GREEN}[+] RAVEN initialized for {self.target}")
        logger.info(f"{Fore.CYAN}[*] Using wordlists from: {self.config.wordlist_dir}")
    
    def _setup_logging(self):
        """Setup logging configuration"""
        global logger
        log_file = os.path.join(self.config.output_dir, f"raven_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        logging.basicConfig(
            level=logging.INFO if not self.config.quiet else logging.WARNING,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler() if not self.config.quiet else logging.NullHandler()
            ]
        )
        logger = logging.getLogger('RAVEN')
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL"""
        if not target.startswith(('http://', 'https://')):
            # Try HTTPS first, then HTTP
            try:
                requests.get(f'https://{target}', timeout=5, verify=False)
                target = f'https://{target}'
            except:
                target = f'http://{target}'
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
        os.makedirs(self.config.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.config.output_dir, "data"), exist_ok=True)
        os.makedirs(os.path.join(self.config.output_dir, "reports"), exist_ok=True)
    
    def _init_results_structure(self) -> Dict:
        """Initialize results data structure"""
        return {
            'metadata': {
                'target': self.target,
                'domain': self.domain,
                'base_domain': self.base_domain,
                'scan_start': datetime.now().isoformat(),
                'framework': 'RAVEN v1.0',
                'analyst': 'Professional Security Team',
                'scope': 'Authorized Security Assessment'
            },
            'reconnaissance': {
                'dns_records': {},
                'subdomains': [],
                'ip_addresses': [],
                'open_ports': {},
                'technology_stack': {},
                'directory_structure': [],
                'endpoints': [],
                'api_discovery': [],
                'cloud_infrastructure': {},
                'ssl_tls_info': {},
                'network_information': {},
                'email_addresses': [],
                'data_exposure': []
            },
            'vulnerability_assessment': {
                'probability_analysis': [],
                'security_headers': {},
                'misconfigurations': [],
                'weak_configurations': [],
                'risk_indicators': []
            },
            'summary': {
                'total_findings': 0,
                'risk_level': 'Unknown',
                'recommendations': [],
                'next_steps': []
            }
        }
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load wordlists from SecLists"""
        wordlists = {}
        
        # Define wordlist paths
        wordlist_paths = {
            'subdomains': [
                '/usr/share/seclists/Discovery/DNS/subdomains.txt',
                '/usr/share/seclists/Discovery/DNS/namelist.txt',
                '/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt'
            ],
            'directories': [
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'
            ],
            'files': [
                '/usr/share/seclists/Discovery/Web-Content/files.txt',
                '/usr/share/seclists/Discovery/Web-Content/CommonBackdoors.txt'
            ],
            'api': [
                '/usr/share/seclists/Discovery/Web-Content/API/endpoints.txt',
                '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt'
            ]
        }
        
        for category, paths in wordlist_paths.items():
            wordlists[category] = []
            for path in paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = [line.strip() for line in f if line.strip()]
                            wordlists[category].extend(lines)
                        logger.info(f"Loaded {len(lines)} items from {path}")
                    except Exception as e:
                        logger.warning(f"Failed to load {path}: {e}")
            
            # Remove duplicates and limit
            wordlists[category] = list(set(wordlists[category]))
            if len(wordlists[category]) > 5000:
                wordlists[category] = wordlists[category][:5000]
        
        return wordlists
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            subprocess.run(['which', tool_name], check=True, capture_output=True)
            return True
        except:
            return False
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with proper configuration"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        if self.config.proxy:
            session.proxies = {'http': self.config.proxy, 'https': self.config.proxy}
        
        session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        return session
    
    def _rate_limit(self):
        """Implement rate limiting"""
        time.sleep(1 / self.config.rate_limit)
        self.stats['requests_made'] += 1
    
    # ==================== CORE RECONNAISSANCE METHODS ====================
    
    def perform_dns_reconnaissance(self):
        """Perform comprehensive DNS reconnaissance"""
        logger.info(f"{Fore.CYAN}[*] Starting DNS reconnaissance...")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'PTR', 'DNSKEY']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.base_domain, record_type)
                self.results['reconnaissance']['dns_records'][record_type] = [
                    str(r) for r in answers
                ]
                logger.info(f"Found {record_type} records: {len(answers)}")
            except Exception as e:
                logger.debug(f"No {record_type} records: {e}")
        
        # Additional DNS checks
        self._check_dns_security()
        self._perform_dns_bruteforce()
    
    def _check_dns_security(self):
        """Check DNS security configurations"""
        try:
            # Check for DNSSEC
            try:
                dns.resolver.resolve(self.base_domain, 'DNSKEY')
                self.results['reconnaissance']['dns_records']['DNSSEC'] = 'Enabled'
                logger.info(f"DNSSEC is enabled")
            except:
                self.results['reconnaissance']['dns_records']['DNSSEC'] = 'Disabled'
                logger.info(f"DNSSEC is disabled")
            
            # Check for DMARC
            try:
                dns.resolver.resolve(f'_dmarc.{self.base_domain}', 'TXT')
                self.results['reconnaissance']['dns_records']['DMARC'] = 'Present'
                logger.info(f"DMARC record found")
            except:
                self.results['reconnaissance']['dns_records']['DMARC'] = 'Absent'
            
            # Check for DKIM
            common_dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim']
            for selector in common_dkim_selectors:
                try:
                    dns.resolver.resolve(f'{selector}._domainkey.{self.base_domain}', 'TXT')
                    self.results['reconnaissance']['dns_records']['DKIM'] = f'Found with selector: {selector}'
                    logger.info(f"DKIM record found with selector: {selector}")
                    break
                except:
                    continue
        
        except Exception as e:
            logger.error(f"DNS security check failed: {e}")
    
    def _perform_dns_bruteforce(self):
        """Perform DNS subdomain brute force"""
        if 'subdomains' not in self.wordlists or not self.wordlists['subdomains']:
            logger.warning("No subdomain wordlist available")
            return
        
        logger.info(f"Starting DNS brute force with {len(self.wordlists['subdomains'])} words")
        
        found_subdomains = []
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            for word in self.wordlists['subdomains'][:2000]:  # Limit for speed
                subdomain = f"{word}.{self.base_domain}"
                futures.append(executor.submit(self._resolve_dns, subdomain))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
        
        # Add unique subdomains to results
        for subdomain in found_subdomains:
            if subdomain not in self.results['reconnaissance']['subdomains']:
                self.results['reconnaissance']['subdomains'].append(subdomain)
        
        logger.info(f"Found {len(found_subdomains)} subdomains")
    
    def _resolve_dns(self, hostname: str) -> Optional[str]:
        """Resolve a hostname"""
        try:
            socket.gethostbyname(hostname)
            logger.info(f"Found subdomain: {hostname}")
            return hostname
        except socket.gaierror:
            return None
        except Exception as e:
            logger.debug(f"Error resolving {hostname}: {e}")
            return None
    
    def perform_port_scanning(self):
        """Perform port scanning with Nmap"""
        logger.info(f"{Fore.CYAN}[*] Starting port scanning...")
        
        if not self.nm:
            logger.warning("Nmap not available")
            return
        
        try:
            # Resolve IP addresses
            ip_addresses = set()
            try:
                ip_addresses.add(socket.gethostbyname(self.domain))
            except:
                pass
            
            # Add subdomain IPs
            for subdomain in self.results['reconnaissance']['subdomains'][:10]:
                try:
                    ip = socket.gethostbyname(subdomain)
                    ip_addresses.add(ip)
                except:
                    continue
            
            # Scan each IP
            for ip in ip_addresses:
                logger.info(f"Scanning {ip}...")
                
                # Quick scan first
                self.nm.scan(ip, arguments='-sS -T4 --top-ports 100')
                
                if ip in self.nm.all_hosts():
                    self.results['reconnaissance']['ip_addresses'].append(ip)
                    self.results['reconnaissance']['open_ports'][ip] = []
                    
                    for proto in self.nm[ip].all_protocols():
                        ports = self.nm[ip][proto].keys()
                        for port in ports:
                            port_info = self.nm[ip][proto][port]
                            service_info = {
                                'port': port,
                                'protocol': proto,
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            }
                            self.results['reconnaissance']['open_ports'][ip].append(service_info)
                            
                            if port_info['state'] == 'open':
                                logger.info(f"Open port: {ip}:{port} - {port_info['name']} {port_info.get('version', '')}")
            
            # Save detailed scan results
            self._save_nmap_results()
            
        except Exception as e:
            logger.error(f"Port scanning failed: {e}")
    
    def _save_nmap_results(self):
        """Save Nmap results to file"""
        if self.nm:
            scan_file = os.path.join(self.config.output_dir, "data", "nmap_scan.xml")
            try:
                with open(scan_file, 'w') as f:
                    f.write(self.nm.get_nmap_last_output())
                logger.info(f"Nmap results saved to {scan_file}")
            except:
                pass
    
    def analyze_technology_stack(self):
        """Analyze the technology stack"""
        logger.info(f"{Fore.CYAN}[*] Analyzing technology stack...")
        
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            content = response.text
            headers = response.headers
            
            # Server information
            tech_info = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', ''),
                'framework': self._detect_framework(content, headers),
                'programming_languages': self._detect_languages(content),
                'javascript_frameworks': self._detect_js_frameworks(content),
                'database_indicators': self._detect_databases(content),
                'cms': self._detect_cms(content),
                'cdn': self._detect_cdn(headers),
                'caching': self._detect_caching(headers),
                'security_headers': self._analyze_security_headers(headers)
            }
            
            self.results['reconnaissance']['technology_stack'] = tech_info
            
            # Log findings
            for key, value in tech_info.items():
                if value:
                    if isinstance(value, list):
                        if value:
                            logger.info(f"{key}: {', '.join(value)}")
                    elif isinstance(value, dict):
                        if value:
                            logger.info(f"{key}: Found {len(value)} items")
                    elif value not in ['', 'Unknown']:
                        logger.info(f"{key}: {value}")
        
        except Exception as e:
            logger.error(f"Technology analysis failed: {e}")
    
    def _detect_framework(self, content: str, headers: Dict) -> List[str]:
        """Detect web frameworks"""
        frameworks = []
        content_lower = content.lower()
        
        framework_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'sites/all', 'sites/default'],
            'Joomla': ['joomla', 'joomla.org', 'com_content'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['django', 'csrfmiddlewaretoken'],
            'Ruby on Rails': ['rails', 'ruby'],
            'Express.js': ['express'],
            'Spring Boot': ['spring'],
            'ASP.NET': ['asp.net', '__viewstate', '__eventvalidation'],
            'Flask': ['flask'],
            'React': ['react', 'react-dom'],
            'Angular': ['angular', 'ng-'],
            'Vue.js': ['vue', 'v-'],
            'Next.js': ['next', '__next'],
            'Nuxt.js': ['nuxt', '_nuxt']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                frameworks.append(framework)
        
        # Check headers
        server_header = headers.get('Server', '').lower()
        if 'apache' in server_header:
            frameworks.append('Apache HTTP Server')
        elif 'nginx' in server_header:
            frameworks.append('Nginx')
        elif 'iis' in server_header:
            frameworks.append('IIS')
        
        return list(set(frameworks))
    
    def _detect_languages(self, content: str) -> List[str]:
        """Detect programming languages"""
        languages = []
        content_lower = content.lower()
        
        language_patterns = {
            'PHP': ['.php', '<?php', 'phpinfo', 'wp-content'],
            'Python': ['.py', 'python/', 'django'],
            'Java': ['.jsp', '.java', 'servlet', 'jvm'],
            'JavaScript': ['.js', 'javascript:', 'node.js'],
            'Ruby': ['.rb', '.erb', 'ruby', 'rails'],
            'ASP.NET': ['.aspx', 'asp.net'],
            'Go': ['go/', 'golang'],
            'Perl': ['.pl', 'perl', 'cgi-bin']
        }
        
        for language, patterns in language_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                languages.append(language)
        
        return list(set(languages))
    
    def _detect_js_frameworks(self, content: str) -> List[str]:
        """Detect JavaScript frameworks"""
        frameworks = []
        content_lower = content.lower()
        
        js_patterns = {
            'jQuery': ['jquery', 'jquery.min.js'],
            'React': ['react', 'react-dom'],
            'Angular': ['angular', 'ng-'],
            'Vue.js': ['vue', 'v-'],
            'Ember.js': ['ember'],
            'Backbone.js': ['backbone'],
            'Meteor': ['meteor'],
            'Three.js': ['three.js'],
            'D3.js': ['d3.js'],
            'Chart.js': ['chart.js']
        }
        
        for framework, patterns in js_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                frameworks.append(framework)
        
        return frameworks
    
    def _detect_databases(self, content: str) -> List[str]:
        """Detect database indicators"""
        databases = []
        content_lower = content.lower()
        
        db_patterns = {
            'MySQL': ['mysql', 'mysqli_'],
            'PostgreSQL': ['postgresql', 'pg_'],
            'MongoDB': ['mongodb', 'mongodb://'],
            'Redis': ['redis', 'redis://'],
            'SQLite': ['sqlite'],
            'Oracle': ['oracle'],
            'SQL Server': ['sql server', 'mssql'],
            'MariaDB': ['mariadb'],
            'Cassandra': ['cassandra'],
            'Elasticsearch': ['elasticsearch']
        }
        
        for db, patterns in db_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                databases.append(db)
        
        return databases
    
    def _detect_cms(self, content: str) -> List[str]:
        """Detect content management systems"""
        cms_list = []
        content_lower = content.lower()
        
        cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'sites/all'],
            'Joomla': ['joomla', 'com_content'],
            'Magento': ['magento', '/static/version'],
            'Shopify': ['shopify'],
            'Wix': ['wix.com'],
            'Squarespace': ['squarespace'],
            'Ghost': ['ghost'],
            'Blogger': ['blogger'],
            'Typo3': ['typo3'],
            'Concrete5': ['concrete5']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                cms_list.append(cms)
        
        return cms_list
    
    def _detect_cdn(self, headers: Dict) -> List[str]:
        """Detect CDN usage"""
        cdns = []
        
        cdn_indicators = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Akamai': ['akamai', 'x-akamai'],
            'Fastly': ['fastly', 'x-served-by'],
            'Amazon CloudFront': ['cloudfront', 'x-amz-cf-'],
            'Google Cloud CDN': ['google', 'gcdn'],
            'Microsoft Azure CDN': ['azure', 'x-azure-ref'],
            'Imperva': ['imperva', 'incapsula'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'StackPath': ['stackpath']
        }
        
        for cdn, indicators in cdn_indicators.items():
            for header, value in headers.items():
                header_lower = header.lower() + value.lower()
                if any(indicator.lower() in header_lower for indicator in indicators):
                    cdns.append(cdn)
                    break
        
        return list(set(cdns))
    
    def _detect_caching(self, headers: Dict) -> Dict:
        """Detect caching mechanisms"""
        caching = {}
        
        cache_headers = ['Cache-Control', 'Expires', 'ETag', 'Last-Modified', 'Pragma']
        for header in cache_headers:
            if header in headers:
                caching[header] = headers[header]
        
        # Check for CDN caching
        if 'Age' in headers:
            caching['CDN-Cache'] = headers['Age']
        
        return caching
    
    def _analyze_security_headers(self, headers: Dict) -> Dict:
        """Analyze security headers"""
        security_headers = {}
        missing_headers = []
        
        important_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-XSS-Protection'
        ]
        
        for header in important_headers:
            if header in headers:
                security_headers[header] = headers[header]
            else:
                missing_headers.append(header)
                security_headers[header] = 'Missing'
        
        # Add analysis
        security_headers['analysis'] = {
            'present': len(security_headers) - len(missing_headers),
            'missing': missing_headers,
            'score': f"{(len(security_headers) - len(missing_headers)) / len(important_headers) * 100:.1f}%"
        }
        
        return security_headers
    
    def discover_directories_and_files(self):
        """Discover directories and files"""
        logger.info(f"{Fore.CYAN}[*] Discovering directories and files...")
        
        if 'directories' not in self.wordlists or not self.wordlists['directories']:
            logger.warning("No directory wordlist available")
            return
        
        discovered = []
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = []
            for directory in self.wordlists['directories'][:1000]:  # Limit for speed
                url = f"{self.target}/{directory}"
                futures.append(executor.submit(self._check_directory, url))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        # Add to results
        self.results['reconnaissance']['directory_structure'] = discovered
        logger.info(f"Discovered {len(discovered)} directories/files")
    
    def _check_directory(self, url: str) -> Optional[Dict]:
        """Check if a directory/file exists"""
        try:
            self._rate_limit()
            response = self.session.get(url, timeout=10, verify=False)
            
            if response.status_code in [200, 301, 302, 403]:
                info = {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'type': self._determine_resource_type(response)
                }
                
                # Check for interesting files
                if self._is_interesting_file(url, response):
                    info['interesting'] = True
                    logger.info(f"Interesting: {url} ({response.status_code})")
                
                return info
        
        except Exception as e:
            return None
        
        return None
    
    def _determine_resource_type(self, response) -> str:
        """Determine the type of resource"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'text/html' in content_type:
            return 'html'
        elif 'application/json' in content_type:
            return 'json'
        elif 'javascript' in content_type:
            return 'javascript'
        elif 'css' in content_type:
            return 'css'
        elif 'image' in content_type:
            return 'image'
        elif 'pdf' in content_type:
            return 'pdf'
        else:
            return 'other'
    
    def _is_interesting_file(self, url: str, response) -> bool:
        """Check if file is interesting for security assessment"""
        interesting_patterns = [
            'admin', 'login', 'config', 'backup', 'dump', 'sql',
            'env', 'secret', 'password', 'credential', 'key',
            'git', 'svn', 'htaccess', 'bash_history', 'ssh',
            'phpinfo', 'test', 'debug', 'console', 'api'
        ]
        
        url_lower = url.lower()
        content_lower = response.text.lower() if response.text else ''
        
        # Check URL patterns
        if any(pattern in url_lower for pattern in interesting_patterns):
            return True
        
        # Check content patterns
        sensitive_patterns = [
            'password', 'secret', 'api_key', 'token', 'aws_',
            'database', 'connection', 'credential', 'private'
        ]
        
        if any(pattern in content_lower for pattern in sensitive_patterns):
            return True
        
        return False
    
    def discover_endpoints_and_apis(self):
        """Discover API endpoints and web endpoints"""
        logger.info(f"{Fore.CYAN}[*] Discovering endpoints and APIs...")
        
        # First, get main page and extract links
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links
            endpoints = set()
            for link in soup.find_all(['a', 'link', 'script', 'img'], href=True):
                href = link['href']
                if href.startswith(('http://', 'https://', '//')):
                    continue
                endpoints.add(href)
            
            for link in soup.find_all(['script', 'img'], src=True):
                src = link['src']
                if src.startswith(('http://', 'https://', '//')):
                    continue
                endpoints.add(src)
            
            # Convert to list and add to results
            endpoint_list = []
            for endpoint in endpoints:
                if endpoint.strip():
                    endpoint_list.append({
                        'endpoint': endpoint,
                        'source': 'html_parsing'
                    })
            
            self.results['reconnaissance']['endpoints'] = endpoint_list[:100]  # Limit
            
            # API discovery
            self._discover_api_endpoints()
            
            logger.info(f"Discovered {len(endpoint_list)} endpoints")
            
        except Exception as e:
            logger.error(f"Endpoint discovery failed: {e}")
    
    def _discover_api_endpoints(self):
        """Discover API endpoints"""
        api_patterns = [
            'api', 'api/v1', 'api/v2', 'api/v3', 'v1', 'v2', 'v3',
            'rest', 'rest/v1', 'graphql', 'soap', 'xmlrpc', 'jsonrpc',
            'oauth', 'auth', 'authenticate', 'token', 'login', 'register',
            'user', 'users', 'account', 'accounts', 'profile', 'profiles',
            'admin', 'administrator', 'dashboard', 'panel', 'control'
        ]
        
        api_endpoints = []
        
        for pattern in api_patterns:
            url = f"{self.target}/{pattern}"
            try:
                self._rate_limit()
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code in [200, 201, 204, 301, 302, 401, 403]:
                    api_info = {
                        'endpoint': pattern,
                        'url': url,
                        'status': response.status_code,
                        'type': self._determine_api_type(response)
                    }
                    api_endpoints.append(api_info)
                    
                    if response.status_code == 200:
                        logger.info(f"API endpoint found: {url}")
            
            except Exception:
                continue
        
        self.results['reconnaissance']['api_discovery'] = api_endpoints
    
    def _determine_api_type(self, response) -> str:
        """Determine API type from response"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'application/json' in content_type:
            return 'REST API'
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            return 'SOAP API'
        elif 'graphql' in content_type or 'graphql' in response.text.lower():
            return 'GraphQL'
        elif 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
            return 'OpenAPI/Swagger'
        else:
            return 'Unknown'
    
    def analyze_ssl_tls(self):
        """Analyze SSL/TLS configuration"""
        logger.info(f"{Fore.CYAN}[*] Analyzing SSL/TLS configuration...")
        
        try:
            # Parse domain for SSL check
            parsed = urlparse(self.target)
            hostname = parsed.netloc.split(':')[0]
            
            # Check SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate info
                    ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'hasExpired': datetime.now() > datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') if 'notAfter' in cert else None
                    }
                    
                    # Check for weak protocols/ciphers (simplified)
                    ssl_info['protocols'] = ['TLSv1.2', 'TLSv1.3']  # Would require more detailed check
                    
                    self.results['reconnaissance']['ssl_tls_info'] = ssl_info
                    
                    # Log findings
                    if ssl_info['hasExpired']:
                        logger.warning(f"SSL certificate has expired: {ssl_info['notAfter']}")
                    else:
                        logger.info(f"SSL certificate valid until: {ssl_info['notAfter']}")
        
        except Exception as e:
            logger.error(f"SSL analysis failed: {e}")
            self.results['reconnaissance']['ssl_tls_info'] = {'error': str(e)}
    
    def check_data_exposure(self):
        """Check for data exposure"""
        logger.info(f"{Fore.CYAN}[*] Checking for data exposure...")
        
        exposure_checks = []
        
        # Common sensitive files
        sensitive_files = [
            '.env', '.env.example', '.env.local', '.env.production',
            'config.php', 'config.json', 'config.yml', 'config.yaml',
            'settings.php', 'settings.json', 'settings.yml', 'settings.yaml',
            'secrets.json', 'secrets.yml', 'secrets.yaml',
            'credentials.json', 'credentials.yml',
            'backup.sql', 'dump.sql', 'database.sql',
            'backup.tar', 'backup.tar.gz', 'backup.zip',
            '.git/HEAD', '.git/config',
            '.svn/entries',
            'wp-config.php',
            'robots.txt',
            'crossdomain.xml',
            'clientaccesspolicy.xml',
            'phpinfo.php',
            'test.php',
            '.htaccess',
            '.htpasswd',
            'web.config'
        ]
        
        for file_path in sensitive_files:
            url = f"{self.target}/{file_path}"
            try:
                self._rate_limit()
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    exposure = {
                        'file': file_path,
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.content),
                        'risk': self._assess_exposure_risk(file_path, response)
                    }
                    exposure_checks.append(exposure)
                    
                    logger.warning(f"Data exposure found: {file_path}")
            
            except Exception:
                continue
        
        self.results['reconnaissance']['data_exposure'] = exposure_checks
        logger.info(f"Found {len(exposure_checks)} potential data exposures")
    
    def _assess_exposure_risk(self, file_path: str, response) -> str:
        """Assess risk level of exposed data"""
        high_risk_files = ['.env', '.htpasswd', 'wp-config.php', 'config.php', 'secrets']
        medium_risk_files = ['.git', '.svn', 'backup', 'dump', 'database']
        low_risk_files = ['robots.txt', 'crossdomain.xml']
        
        file_lower = file_path.lower()
        
        if any(risk_file in file_lower for risk_file in high_risk_files):
            return 'High'
        elif any(risk_file in file_lower for risk_file in medium_risk_files):
            return 'Medium'
        elif any(risk_file in file_lower for risk_file in low_risk_files):
            return 'Low'
        
        # Check content for sensitive data
        content = response.text.lower()
        sensitive_patterns = [
            'password=', 'secret=', 'api_key=', 'token=', 'aws_',
            'database_password', 'db_pass', 'private_key'
        ]
        
        if any(pattern in content for pattern in sensitive_patterns):
            return 'High'
        
        return 'Medium'
    
    def harvest_email_addresses(self):
        """Harvest email addresses from the target"""
        logger.info(f"{Fore.CYAN}[*] Harvesting email addresses...")
        
        emails = set()
        
        try:
            # Check main page
            response = self.session.get(self.target, timeout=self.config.timeout)
            found_emails = self._extract_emails(response.text)
            emails.update(found_emails)
            
            # Check contact pages
            contact_pages = ['contact', 'contact-us', 'about', 'team', 'support']
            for page in contact_pages:
                url = f"{self.target}/{page}"
                try:
                    self._rate_limit()
                    response = self.session.get(url, timeout=10, verify=False)
                    if response.status_code == 200:
                        found_emails = self._extract_emails(response.text)
                        emails.update(found_emails)
                except:
                    continue
            
            # Convert to list
            email_list = list(emails)
            self.results['reconnaissance']['email_addresses'] = email_list
            
            logger.info(f"Found {len(email_list)} email addresses")
            
        except Exception as e:
            logger.error(f"Email harvesting failed: {e}")
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        
        # Filter by domain
        domain_emails = []
        for email in emails:
            if self.base_domain in email:
                domain_emails.append(email)
        
        return domain_emails
    
    def analyze_cloud_infrastructure(self):
        """Analyze cloud infrastructure"""
        logger.info(f"{Fore.CYAN}[*] Analyzing cloud infrastructure...")
        
        cloud_info = {}
        
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            headers = response.headers
            
            # Detect cloud provider
            providers = self._detect_cloud_provider(headers)
            if providers:
                cloud_info['providers'] = providers
            
            # Detect hosting type
            hosting = self._detect_hosting_type(headers)
            if hosting:
                cloud_info['hosting'] = hosting
            
            # Check for common cloud services
            services = self._detect_cloud_services(headers)
            if services:
                cloud_info['services'] = services
            
            self.results['reconnaissance']['cloud_infrastructure'] = cloud_info
            
            # Log findings
            if providers:
                logger.info(f"Cloud providers detected: {', '.join(providers)}")
            if hosting:
                logger.info(f"Hosting type: {hosting}")
        
        except Exception as e:
            logger.error(f"Cloud analysis failed: {e}")
    
    def _detect_cloud_provider(self, headers: Dict) -> List[str]:
        """Detect cloud provider from headers"""
        providers = []
        
        provider_indicators = {
            'AWS': ['x-amz-', 'amazon', 'aws', 'ec2', 's3'],
            'Azure': ['azure', 'microsoft', 'windows-azure'],
            'Google Cloud': ['google', 'gcp', 'gce', 'google-cloud'],
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'Fastly': ['fastly', 'x-served-by'],
            'Akamai': ['akamai', 'x-akamai'],
            'Heroku': ['heroku', 'x-powered-by: heroku'],
            'DigitalOcean': ['digitalocean', 'do'],
            'Linode': ['linode'],
            'Vultr': ['vultr']
        }
        
        for provider, indicators in provider_indicators.items():
            for indicator in indicators:
                for header, value in headers.items():
                    if indicator.lower() in (header.lower() + value.lower()):
                        providers.append(provider)
                        break
                if provider in providers:
                    break
        
        return list(set(providers))
    
    def _detect_hosting_type(self, headers: Dict) -> str:
        """Detect hosting type"""
        server = headers.get('Server', '').lower()
        
        if 'cloudflare' in server:
            return 'CDN/Proxy'
        elif 'nginx' in server or 'apache' in server:
            return 'VPS/Dedicated Server'
        elif 'iis' in server:
            return 'Windows Server'
        elif 'heroku' in server:
            return 'PaaS'
        else:
            return 'Unknown'
    
    def _detect_cloud_services(self, headers: Dict) -> List[str]:
        """Detect cloud services"""
        services = []
        
        service_indicators = {
            'S3/Cloud Storage': ['x-amz-bucket', 'amazonaws.com/s3'],
            'CloudFront': ['cloudfront', 'x-amz-cf-'],
            'Load Balancer': ['x-lb', 'load-balancer'],
            'WAF': ['x-waf', 'awselb/', 'cloudflare-waf'],
            'API Gateway': ['x-apigw', 'apigateway']
        }
        
        for service, indicators in service_indicators.items():
            for indicator in indicators:
                for header, value in headers.items():
                    if indicator.lower() in (header.lower() + value.lower()):
                        services.append(service)
                        break
        
        return list(set(services))
    
    def perform_vulnerability_probability_analysis(self):
        """Analyze probability of vulnerabilities based on findings"""
        logger.info(f"{Fore.CYAN}[*] Performing vulnerability probability analysis...")
        
        probabilities = []
        
        # Check for common vulnerability indicators
        probabilities.extend(self._check_sqli_probability())
        probabilities.extend(self._check_xss_probability())
        probabilities.extend(self._check_insecure_direct_object_references())
        probabilities.extend(self._check_security_misconfigurations())
        probabilities.extend(self._check_sensitive_data_exposure())
        probabilities.extend(self._check_broken_authentication())
        probabilities.extend(self._check_xml_external_entities())
        probabilities.extend(self._check_broken_access_control())
        probabilities.extend(self._check_insecure_deserialization())
        probabilities.extend(self._check_components_with_known_vulnerabilities())
        probabilities.extend(self._check_insufficient_logging_monitoring())
        
        # Sort by probability
        probabilities.sort(key=lambda x: x['probability'], reverse=True)
        
        self.results['vulnerability_assessment']['probability_analysis'] = probabilities
        
        # Log top findings
        for vuln in probabilities[:10]:
            logger.info(f"Vulnerability probability - {vuln['type']}: {vuln['probability']}%")
    
    def _check_sqli_probability(self) -> List[Dict]:
        """Check SQL Injection probability"""
        indicators = []
        
        # Check for dynamic parameters
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            if '?' in response.url:
                indicators.append({
                    'type': 'SQL Injection',
                    'indicator': 'Dynamic URL parameters found',
                    'probability': 30,
                    'recommendation': 'Test parameters with SQLi payloads',
                    'confidence': 'Medium'
                })
        except:
            pass
        
        # Check for database indicators
        tech_stack = self.results['reconnaissance'].get('technology_stack', {})
        databases = tech_stack.get('database_indicators', [])
        if databases:
            indicators.append({
                'type': 'SQL Injection',
                'indicator': f'Database technology detected: {", ".join(databases)}',
                'probability': 40,
                'recommendation': 'Perform SQL injection testing on all input vectors',
                'confidence': 'High'
            })
        
        # Check for error messages
        if self._check_for_database_errors():
            indicators.append({
                'type': 'SQL Injection',
                'indicator': 'Database error messages in responses',
                'probability': 60,
                'recommendation': 'Test for verbose error-based SQL injection',
                'confidence': 'High'
            })
        
        return indicators
    
    def _check_xss_probability(self) -> List[Dict]:
        """Check Cross-Site Scripting probability"""
        indicators = []
        
        # Check for input fields
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Count input fields
            input_fields = soup.find_all(['input', 'textarea'])
            if len(input_fields) > 0:
                indicators.append({
                    'type': 'Cross-Site Scripting',
                    'indicator': f'{len(input_fields)} input fields found',
                    'probability': 50,
                    'recommendation': 'Test all input fields for XSS vulnerabilities',
                    'confidence': 'High'
                })
        except:
            pass
        
        # Check for reflected parameters
        parsed = urlparse(self.target)
        if parsed.query:
            indicators.append({
                'type': 'Cross-Site Scripting',
                'indicator': 'URL parameters present',
                'probability': 40,
                'recommendation': 'Test parameters for reflected XSS',
                'confidence': 'Medium'
            })
        
        return indicators
    
    def _check_for_database_errors(self) -> bool:
        """Check for database error messages in responses"""
        error_patterns = [
            'sql', 'mysql', 'postgresql', 'oracle', 'database',
            'syntax error', 'unclosed quotation', 'you have an error',
            'warning:', 'notice:', 'undefined index'
        ]
        
        try:
            response = self.session.get(self.target + "/test'", timeout=10, verify=False)
            content_lower = response.text.lower()
            return any(pattern in content_lower for pattern in error_patterns)
        except:
            return False
    
    def _check_insecure_direct_object_references(self) -> List[Dict]:
        """Check for IDOR probability"""
        indicators = []
        
        # Look for numeric IDs in discovered endpoints
        endpoints = self.results['reconnaissance'].get('endpoints', [])
        for endpoint in endpoints:
            ep = endpoint.get('endpoint', '')
            if any(pattern in ep for pattern in ['id=', 'user=', 'account=', 'file=']):
                indicators.append({
                    'type': 'Insecure Direct Object References',
                    'indicator': f'Parameter found in endpoint: {ep}',
                    'probability': 70,
                    'recommendation': 'Test for IDOR by modifying parameter values',
                    'confidence': 'High'
                })
        
        return indicators
    
    def _check_security_misconfigurations(self) -> List[Dict]:
        """Check for security misconfigurations"""
        indicators = []
        
        # Check security headers
        tech_stack = self.results['reconnaissance'].get('technology_stack', {})
        security_headers = tech_stack.get('security_headers', {})
        
        missing_headers = []
        for header, value in security_headers.items():
            if value == 'Missing' and header != 'analysis':
                missing_headers.append(header)
        
        if missing_headers:
            indicators.append({
                'type': 'Security Misconfiguration',
                'indicator': f'Missing security headers: {", ".join(missing_headers)}',
                'probability': 80,
                'recommendation': 'Implement missing security headers',
                'confidence': 'High'
            })
        
        # Check for default files
        default_files = ['readme', 'install', 'setup', 'test', 'example']
        directories = self.results['reconnaissance'].get('directory_structure', [])
        for directory in directories:
            url = directory.get('url', '').lower()
            if any(df in url for df in default_files):
                indicators.append({
                    'type': 'Security Misconfiguration',
                    'indicator': f'Default/example file found: {url}',
                    'probability': 60,
                    'recommendation': 'Remove default/example files',
                    'confidence': 'Medium'
                })
        
        return indicators
    
    def _check_sensitive_data_exposure(self) -> List[Dict]:
        """Check for sensitive data exposure"""
        indicators = []
        
        data_exposure = self.results['reconnaissance'].get('data_exposure', [])
        if data_exposure:
            high_risk_files = [d for d in data_exposure if d.get('risk') == 'High']
            
            if high_risk_files:
                indicators.append({
                    'type': 'Sensitive Data Exposure',
                    'indicator': f'{len(high_risk_files)} high-risk files exposed',
                    'probability': 90,
                    'recommendation': 'Immediately secure exposed sensitive files',
                    'confidence': 'High'
                })
        
        return indicators
    
    def _check_broken_authentication(self) -> List[Dict]:
        """Check for broken authentication"""
        indicators = []
        
        # Look for login pages
        directories = self.results['reconnaissance'].get('directory_structure', [])
        login_pages = ['login', 'signin', 'auth', 'authenticate', 'admin']
        
        for directory in directories:
            url = directory.get('url', '').lower()
            if any(lp in url for lp in login_pages):
                indicators.append({
                    'type': 'Broken Authentication',
                    'indicator': f'Authentication page found: {url}',
                    'probability': 50,
                    'recommendation': 'Test for authentication bypass and brute force',
                    'confidence': 'Medium'
                })
                break
        
        return indicators
    
    def _check_xml_external_entities(self) -> List[Dict]:
        """Check for XXE probability"""
        indicators = []
        
        # Look for XML endpoints
        api_endpoints = self.results['reconnaissance'].get('api_discovery', [])
        for endpoint in api_endpoints:
            ep_type = endpoint.get('type', '')
            if 'XML' in ep_type or 'SOAP' in ep_type:
                indicators.append({
                    'type': 'XML External Entities',
                    'indicator': f'XML-based endpoint found: {endpoint.get("endpoint")}',
                    'probability': 40,
                    'recommendation': 'Test for XXE vulnerabilities',
                    'confidence': 'Medium'
                })
        
        return indicators
    
    def _check_broken_access_control(self) -> List[Dict]:
        """Check for broken access control"""
        indicators = []
        
        # Look for admin/privileged endpoints
        directories = self.results['reconnaissance'].get('directory_structure', [])
        admin_pages = ['admin', 'administrator', 'dashboard', 'panel', 'control']
        
        for directory in directories:
            url = directory.get('url', '').lower()
            if any(ap in url for ap in admin_pages):
                indicators.append({
                    'type': 'Broken Access Control',
                    'indicator': f'Privileged endpoint found: {url}',
                    'probability': 60,
                    'recommendation': 'Test for unauthorized access to privileged areas',
                    'confidence': 'High'
                })
        
        return indicators
    
    def _check_insecure_deserialization(self) -> List[Dict]:
        """Check for insecure deserialization"""
        indicators = []
        
        # Look for serialized data patterns
        try:
            response = self.session.get(self.target, timeout=self.config.timeout)
            content = response.text
            
            # Check for common serialization patterns
            serialization_patterns = [
                'serialized', 'deserialize', 'base64', 'json',
                'php_serialize', 'java.io.serializable'
            ]
            
            if any(pattern in content.lower() for pattern in serialization_patterns):
                indicators.append({
                    'type': 'Insecure Deserialization',
                    'indicator': 'Serialization patterns detected',
                    'probability': 30,
                    'recommendation': 'Test for deserialization vulnerabilities',
                    'confidence': 'Low'
                })
        except:
            pass
        
        return indicators
    
    def _check_components_with_known_vulnerabilities(self) -> List[Dict]:
        """Check for components with known vulnerabilities"""
        indicators = []
        
        tech_stack = self.results['reconnaissance'].get('technology_stack', {})
        
        # Check for outdated technologies
        outdated_indicators = [
            ('PHP', ['php/5.', 'php/7.0', 'php/7.1']),
            ('Apache', ['apache/2.2', 'apache/2.0']),
            ('nginx', ['nginx/1.0', 'nginx/1.2']),
            ('WordPress', ['wordpress']),  # Would need version check
            ('Joomla', ['joomla']),  # Would need version check
            ('Drupal', ['drupal'])   # Would need version check
        ]
        
        server_info = tech_stack.get('server', '').lower()
        frameworks = tech_stack.get('framework', [])
        
        for tech, patterns in outdated_indicators:
            if any(pattern in server_info for pattern in patterns) or tech in frameworks:
                indicators.append({
                    'type': 'Components with Known Vulnerabilities',
                    'indicator': f'Potentially outdated technology: {tech}',
                    'probability': 70,
                    'recommendation': 'Update to latest version and patch regularly',
                    'confidence': 'Medium'
                })
        
        return indicators
    
    def _check_insufficient_logging_monitoring(self) -> List[Dict]:
        """Check for insufficient logging and monitoring"""
        indicators = []
        
        # Check for error reporting
        try:
            # Trigger a 404 to check error handling
            response = self.session.get(self.target + "/nonexistentpage12345", 
                                      timeout=10, verify=False)
            
            # Check for verbose errors
            error_indicators = [
                'stack trace', 'exception', 'error at line',
                'warning:', 'notice:', 'fatal error'
            ]
            
            content_lower = response.text.lower()
            if any(ei in content_lower for ei in error_indicators):
                indicators.append({
                    'type': 'Insufficient Logging & Monitoring',
                    'indicator': 'Verbose error messages exposed',
                    'probability': 40,
                    'recommendation': 'Disable verbose errors in production',
                    'confidence': 'Medium'
                })
        except:
            pass
        
        return indicators
    
    def generate_risk_assessment(self):
        """Generate overall risk assessment"""
        logger.info(f"{Fore.CYAN}[*] Generating risk assessment...")
        
        # Calculate risk score
        risk_score = 0
        findings = []
        
        # Data exposure risk
        data_exposure = self.results['reconnaissance'].get('data_exposure', [])
        high_risk_exposures = len([d for d in data_exposure if d.get('risk') == 'High'])
        if high_risk_exposures > 0:
            risk_score += 30
            findings.append(f"{high_risk_exposures} high-risk data exposures found")
        
        # Missing security headers
        tech_stack = self.results['reconnaissance'].get('technology_stack', {})
        security_headers = tech_stack.get('security_headers', {})
        missing_headers = 0
        for header, value in security_headers.items():
            if value == 'Missing' and header != 'analysis':
                missing_headers += 1
        
        if missing_headers > 3:
            risk_score += 25
            findings.append(f"{missing_headers} critical security headers missing")
        elif missing_headers > 0:
            risk_score += 15
        
        # Open ports risk
        open_ports = self.results['reconnaissance'].get('open_ports', {})
        risky_ports = []
        for ip, ports in open_ports.items():
            for port_info in ports:
                if port_info.get('state') == 'open':
                    port = port_info.get('port', 0)
                    service = port_info.get('service', '').lower()
                    
                    # Check for risky services
                    risky_services = ['ftp', 'telnet', 'smtp', 'vnc', 'rdp']
                    if any(rs in service for rs in risky_services):
                        risky_ports.append(f"{ip}:{port} ({service})")
                    
                    # Check for high ports
                    if port in [21, 22, 23, 25, 110, 143, 445, 3389]:
                        risky_ports.append(f"{ip}:{port}")
        
        if risky_ports:
            risk_score += 20
            findings.append(f"Risky open ports: {', '.join(risky_ports[:5])}")
        
        # Vulnerability probabilities
        probabilities = self.results['vulnerability_assessment'].get('probability_analysis', [])
        high_prob_vulns = [p for p in probabilities if p.get('probability', 0) >= 70]
        if high_prob_vulns:
            risk_score += 25
            findings.append(f"{len(high_prob_vulns)} high-probability vulnerabilities identified")
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        elif risk_score >= 10:
            risk_level = "Low"
        else:
            risk_level = "Informational"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        # Generate next steps
        next_steps = self._generate_next_steps()
        
        # Update summary
        self.results['summary'] = {
            'total_findings': len(findings),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'key_findings': findings[:10],  # Top 10 findings
            'recommendations': recommendations,
            'next_steps': next_steps
        }
        
        logger.info(f"Risk Assessment: {risk_level} ({risk_score}/100)")
    
    def _generate_recommendations(self, findings: List[str]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # General recommendations
        recommendations.append("Implement regular security assessments and penetration testing")
        recommendations.append("Establish a vulnerability management program")
        recommendations.append("Ensure proper security headers are implemented")
        
        # Specific recommendations based on findings
        if any("data exposure" in f.lower() for f in findings):
            recommendations.append("Immediately secure exposed sensitive files and data")
            recommendations.append("Implement proper access controls for sensitive resources")
        
        if any("security headers" in f.lower() for f in findings):
            recommendations.append("Implement missing security headers (CSP, HSTS, etc.)")
        
        if any("open ports" in f.lower() for f in findings):
            recommendations.append("Close unnecessary open ports and services")
            recommendations.append("Implement firewall rules to restrict access")
        
        if any("vulnerability" in f.lower() for f in findings):
            recommendations.append("Perform thorough vulnerability testing based on probability analysis")
            recommendations.append("Implement secure coding practices and training")
        
        return recommendations[:10]  # Limit to 10 recommendations
    
    def _generate_next_steps(self) -> List[str]:
        """Generate next steps for further assessment"""
        next_steps = []
        
        # Based on findings
        probabilities = self.results['vulnerability_assessment'].get('probability_analysis', [])
        
        # Sort by probability
        high_prob = [p for p in probabilities if p.get('probability', 0) >= 70]
        medium_prob = [p for p in probabilities if 40 <= p.get('probability', 0) < 70]
        
        if high_prob:
            next_steps.append("Immediate testing required for high-probability vulnerabilities")
            for vuln in high_prob[:3]:
                next_steps.append(f"Test for {vuln['type']} - {vuln['recommendation']}")
        
        if medium_prob:
            next_steps.append("Schedule testing for medium-probability vulnerabilities")
        
        # Additional recon steps
        if self.results['reconnaissance'].get('subdomains'):
            next_steps.append("Perform in-depth assessment of discovered subdomains")
        
        if self.results['reconnaissance'].get('api_discovery'):
            next_steps.append("Conduct comprehensive API security testing")
        
        # Tool recommendations
        next_steps.append("Consider using specialized tools: Burp Suite, OWASP ZAP, Nuclei")
        next_steps.append("Perform authenticated testing if credentials are available")
        
        return next_steps[:10]  # Limit to 10 next steps
    
    def generate_comprehensive_report(self):
        """Generate comprehensive report in a single document"""
        logger.info(f"{Fore.CYAN}[*] Generating comprehensive report...")
        
        report_file = os.path.join(self.config.output_dir, "reports", "RAVEN_Report.md")
        
        with open(report_file, 'w') as f:
            # Header
            f.write("# RAVEN - Reconnaissance Analysis Report\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Analyst:** Professional Security Team\n")
            f.write(f"**Framework:** RAVEN v1.0 by Yx0R\n\n")
            
            f.write("---\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            summary = self.results['summary']
            f.write(f"**Overall Risk Level:** {summary['risk_level']}\n")
            f.write(f"**Risk Score:** {summary['risk_score']}/100\n")
            f.write(f"**Total Findings:** {summary['total_findings']}\n\n")
            
            if summary['key_findings']:
                f.write("### Key Findings\n")
                for finding in summary['key_findings']:
                    f.write(f"- {finding}\n")
                f.write("\n")
            
            f.write("---\n\n")
            
            # Detailed Reconnaissance Findings
            f.write("## Detailed Reconnaissance Findings\n\n")
            
            # DNS Information
            dns_records = self.results['reconnaissance'].get('dns_records', {})
            if dns_records:
                f.write("### DNS Records\n")
                for record_type, records in dns_records.items():
                    if records:
                        f.write(f"**{record_type}:**\n")
                        for record in records:
                            f.write(f"- {record}\n")
                        f.write("\n")
            
            # Subdomains
            subdomains = self.results['reconnaissance'].get('subdomains', [])
            if subdomains:
                f.write(f"### Subdomains Found ({len(subdomains)})\n")
                for subdomain in subdomains[:20]:  # Limit to 20
                    f.write(f"- {subdomain}\n")
                if len(subdomains) > 20:
                    f.write(f"- ... and {len(subdomains) - 20} more\n")
                f.write("\n")
            
            # Technology Stack
            tech_stack = self.results['reconnaissance'].get('technology_stack', {})
            if tech_stack:
                f.write("### Technology Stack Analysis\n")
                for key, value in tech_stack.items():
                    if value and key != 'security_headers':
                        if isinstance(value, list):
                            if value:
                                f.write(f"**{key}:** {', '.join(value)}\n")
                        elif isinstance(value, dict):
                            if value:
                                f.write(f"**{key}:** Found {len(value)} items\n")
                        elif value not in ['', 'Unknown']:
                            f.write(f"**{key}:** {value}\n")
                f.write("\n")
                
                # Security Headers
                security_headers = tech_stack.get('security_headers', {})
                if security_headers:
                    f.write("#### Security Headers Analysis\n")
                    present = 0
                    total = 0
                    for header, status in security_headers.items():
                        if header != 'analysis':
                            total += 1
                            if status != 'Missing':
                                present += 1
                            f.write(f"- **{header}:** {status}\n")
                    
                    if 'analysis' in security_headers:
                        f.write(f"\n**Score:** {security_headers['analysis']['score']}\n")
                    f.write("\n")
            
            # Open Ports
            open_ports = self.results['reconnaissance'].get('open_ports', {})
            if open_ports:
                f.write("### Open Ports\n")
                for ip, ports in open_ports.items():
                    f.write(f"**{ip}:**\n")
                    for port_info in ports:
                        if port_info.get('state') == 'open':
                            f.write(f"- Port {port_info['port']}/{port_info['protocol']}: ")
                            f.write(f"{port_info['service']} {port_info.get('version', '')}\n")
                    f.write("\n")
            
            # Data Exposure
            data_exposure = self.results['reconnaissance'].get('data_exposure', [])
            if data_exposure:
                f.write("### Data Exposure Findings\n")
                for exposure in data_exposure:
                    f.write(f"- **{exposure['file']}** ({exposure['risk']} risk)\n")
                    f.write(f"  - URL: {exposure['url']}\n")
                    f.write(f"  - Status: {exposure['status']}\n")
                    f.write(f"  - Size: {exposure['size']} bytes\n")
                f.write("\n")
            
            # API Discovery
            api_discovery = self.results['reconnaissance'].get('api_discovery', [])
            if api_discovery:
                f.write("### API Endpoints Discovered\n")
                for api in api_discovery:
                    f.write(f"- **{api['endpoint']}** ({api['type']})\n")
                    f.write(f"  - URL: {api['url']}\n")
                    f.write(f"  - Status: {api['status']}\n")
                f.write("\n")
            
            f.write("---\n\n")
            
            # Vulnerability Probability Analysis
            f.write("## Vulnerability Probability Analysis\n\n")
            
            probabilities = self.results['vulnerability_assessment'].get('probability_analysis', [])
            if probabilities:
                # Group by probability
                high_prob = [p for p in probabilities if p.get('probability', 0) >= 70]
                medium_prob = [p for p in probabilities if 40 <= p.get('probability', 0) < 70]
                low_prob = [p for p in probabilities if p.get('probability', 0) < 40]
                
                if high_prob:
                    f.write("### High Probability (≥70%)\n")
                    for vuln in high_prob:
                        f.write(f"#### {vuln['type']}\n")
                        f.write(f"- **Probability:** {vuln['probability']}%\n")
                        f.write(f"- **Indicator:** {vuln['indicator']}\n")
                        f.write(f"- **Recommendation:** {vuln['recommendation']}\n")
                        f.write(f"- **Confidence:** {vuln.get('confidence', 'Medium')}\n\n")
                
                if medium_prob:
                    f.write("### Medium Probability (40-69%)\n")
                    for vuln in medium_prob[:10]:  # Limit to 10
                        f.write(f"- **{vuln['type']}:** {vuln['probability']}% - {vuln['indicator']}\n")
                    f.write("\n")
                
                if low_prob:
                    f.write("### Low Probability (<40%)\n")
                    for vuln in low_prob[:5]:  # Limit to 5
                        f.write(f"- {vuln['type']}: {vuln['probability']}%\n")
                    f.write("\n")
            
            f.write("---\n\n")
            
            # Recommendations and Next Steps
            f.write("## Recommendations & Next Steps\n\n")
            
            f.write("### Critical Recommendations\n")
            recommendations = self.results['summary'].get('recommendations', [])
            for i, rec in enumerate(recommendations[:5], 1):
                f.write(f"{i}. {rec}\n")
            f.write("\n")
            
            f.write("### Suggested Next Steps\n")
            next_steps = self.results['summary'].get('next_steps', [])
            for i, step in enumerate(next_steps[:5], 1):
                f.write(f"{i}. {step}\n")
            f.write("\n")
            
            f.write("---\n\n")
            
            # Appendix
            f.write("## Appendix\n\n")
            
            f.write("### Scan Details\n")
            f.write(f"- **Scan Duration:** {time.time() - self.stats['start_time']:.2f} seconds\n")
            f.write(f"- **Requests Made:** {self.stats['requests_made']}\n")
            f.write(f"- **Modules Executed:** {len(self.config.modules)}\n")
            f.write(f"- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("### Tools Used\n")
            f.write("- RAVEN Framework v1.0\n")
            f.write("- Nmap\n")
            f.write("- Python Requests\n")
            f.write("- BeautifulSoup\n")
            f.write("- DNSPython\n\n")
            
            f.write("### References\n")
            f.write("- OWASP Testing Guide\n")
            f.write("- MITRE ATT&CK Framework\n")
            f.write("- NIST Cybersecurity Framework\n\n")
            
            f.write("---\n\n")
            
            # Footer
            f.write("## Disclaimer\n\n")
            f.write("This report is for **authorized security testing only**. All findings should be verified and validated by qualified security professionals.\n\n")
            f.write("**Unauthorized access to computer systems is illegal and unethical.**\n\n")
            f.write("© 2024 RAVEN Framework by Yx0R. All rights reserved.\n")
        
        logger.info(f"Report generated: {report_file}")
        
        # Also generate JSON report for programmatic access
        json_file = os.path.join(self.config.output_dir, "reports", "RAVEN_Report.json")
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {json_file}")
    
    def run_comprehensive_scan(self):
        """Run comprehensive reconnaissance scan"""
        logger.info(f"{Fore.MAGENTA}{'='*80}")
        logger.info(f"{Fore.MAGENTA}[*] RAVEN - Comprehensive Reconnaissance Scan")
        logger.info(f"{Fore.MAGENTA}[*] Target: {self.target}")
        logger.info(f"{Fore.MAGENTA}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"{Fore.MAGENTA}{'='*80}")
        
        try:
            # Run modules based on configuration
            modules_to_run = {
                RavenModule.DNS: self.perform_dns_reconnaissance,
                RavenModule.SUBDOMAINS: self.perform_dns_reconnaissance,  # Included in DNS recon
                RavenModule.PORTS: self.perform_port_scanning,
                RavenModule.TECH: self.analyze_technology_stack,
                RavenModule.DIRS: self.discover_directories_and_files,
                RavenModule.ENDPOINTS: self.discover_endpoints_and_apis,
                RavenModule.DATA: self.check_data_exposure,
                RavenModule.CLOUD: self.analyze_cloud_infrastructure,
                RavenModule.SSL: self.analyze_ssl_tls,
                RavenModule.EMAIL: self.harvest_email_addresses,
                RavenModule.NETWORK: self.perform_port_scanning,  # Included in port scanning
                RavenModule.APIS: self.discover_endpoints_and_apis,  # Included in endpoint discovery
                RavenModule.VULN_PROBABILITY: self.perform_vulnerability_probability_analysis
            }
            
            # Execute enabled modules
            for module in self.config.modules:
                if module in modules_to_run:
                    try:
                        logger.info(f"{Fore.CYAN}[*] Running module: {module.value}")
                        modules_to_run[module]()
                    except Exception as e:
                        logger.error(f"Module {module.value} failed: {e}")
            
            # Generate risk assessment
            self.generate_risk_assessment()
            
            # Generate report
            self.generate_comprehensive_report()
            
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
            self.generate_comprehensive_report()
        except Exception as e:
            logger.error(f"{Fore.RED}[!] Scan failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}📊 RAVEN SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*80}")
        
        summary = self.results['summary']
        
        stats = [
            (f"{Fore.GREEN}🎯 Target", self.target),
            (f"{Fore.YELLOW}⚠️ Risk Level", f"{summary['risk_level']} ({summary['risk_score']}/100)"),
            (f"{Fore.GREEN}🌐 Subdomains Found", str(len(self.results['reconnaissance']['subdomains']))),
            (f"{Fore.RED}🔓 Data Exposures", str(len(self.results['reconnaissance']['data_exposure']))),
            (f"{Fore.BLUE}🔧 Technologies", str(len(self.results['reconnaissance']['technology_stack']))),
            (f"{Fore.MAGENTA}📈 Vulnerability Probabilities", str(len(self.results['vulnerability_assessment']['probability_analysis']))),
            (f"{Fore.CYAN}⏱️ Scan Duration", f"{time.time() - self.stats['start_time']:.2f}s")
        ]
        
        for label, value in stats:
            print(f"{label}: {Fore.WHITE}{value}")
        
        print(f"\n{Fore.YELLOW}📋 Top Findings:")
        for finding in summary.get('key_findings', [])[:3]:
            print(f"  • {finding}")
        
        print(f"\n{Fore.GREEN}🚀 Next Steps:")
        for step in summary.get('next_steps', [])[:3]:
            print(f"  • {step}")
        
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}📁 Report saved to: {self.config.output_dir}/reports/RAVEN_Report.md")
        print(f"{Fore.CYAN}{'='*80}")


def main():
    """Main entry point"""
    # Check root privileges first
    DependencyManager.check_root()
    
    # Check and install dependencies
    DependencyManager.check_dependencies()
    
    parser = argparse.ArgumentParser(
        description='RAVEN - Reconnaissance Analysis & Vulnerability Enumeration Network',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 raven.py https://example.com
  sudo python3 raven.py example.com --output /opt/raven_results
  sudo python3 raven.py target.com --modules dns_recon tech_stack
  sudo python3 raven.py https://test.com --depth 3 --threads 50

Available Modules:
  dns_recon, subdomain_enum, port_scanning, tech_stack,
  directory_enum, endpoint_discovery, data_exposure,
  cloud_config, ssl_analysis, email_harvesting,
  network_mapping, api_discovery, vulnerability_probability

Developed by Yx0R - For authorized security testing only.
        """
    )
    
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('-o', '--output', default='raven_results',
                       help='Output directory (default: raven_results)')
    parser.add_argument('-t', '--threads', type=int, default=25,
                       help='Number of threads (default: 25)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--user-agent', default=None,
                       help='Custom user agent string')
    parser.add_argument('--wordlist-dir', default='/usr/share/seclists',
                       help='Path to wordlists directory (default: /usr/share/seclists)')
    parser.add_argument('--modules', nargs='+', default=['all'],
                       help='Modules to run (default: all)')
    parser.add_argument('--depth', type=int, choices=[1, 2, 3], default=2,
                       help='Scan depth: 1=Light, 2=Standard, 3=Aggressive (default: 2)')
    parser.add_argument('--proxy', help='Proxy server (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--rate-limit', type=int, default=10,
                       help='Requests per second (default: 10)')
    parser.add_argument('--quiet', action='store_true',
                       help='Quiet mode (suppress output)')
    
    args = parser.parse_args()
    
    # Parse modules
    modules = []
    if 'all' in args.modules:
        modules = list(RavenModule)
    else:
        for module_name in args.modules:
            try:
                module = RavenModule(module_name)
                modules.append(module)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid module: {module_name}")
                sys.exit(1)
    
    # Create configuration
    config = RavenConfig(
        target=args.target,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent or "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
        wordlist_dir=args.wordlist_dir,
        modules=modules,
        depth=args.depth,
        proxy=args.proxy,
        rate_limit=args.rate_limit,
        quiet=args.quiet
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
{Fore.YELLOW}Reconnaissance Analysis & Vulnerability Enumeration Network
{Fore.RED}           DEVELOPED BY Yx0R - FOR AUTHORIZED TESTING ONLY
{Fore.MAGENTA}{'='*80}{Fore.RESET}
{Fore.CYAN}[*] Target: {args.target}
{Fore.CYAN}[*] Modules: {', '.join([m.value for m in modules][:5])}...
{Fore.CYAN}[*] Depth: {args.depth} ({'Light' if args.depth == 1 else 'Standard' if args.depth == 2 else 'Aggressive'})
{Fore.CYAN}[*] Threads: {args.threads}
{Fore.MAGENTA}{'='*80}{Fore.RESET}
"""
    print(banner)
    
    try:
        # Create and run framework
        framework = RavenFramework(config)
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
