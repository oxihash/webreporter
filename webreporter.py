#!/usr/bin/env python3
"""
WebReporter - Advanced Professional Penetration Testing Framework
A comprehensive, enterprise-grade security assessment tool for authorized testing only.

Legal Notice: This tool is for authorized penetration testing only.
Unauthorized access to computer systems is illegal.
"""

import argparse
import json
import subprocess
import sys
import time
import socket
import dns.resolver
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from collections import defaultdict
import hashlib


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ToolChecker:
    """Verify required tools are installed"""
    REQUIRED_TOOLS = {
        'nmap': 'Network reconnaissance',
        'nuclei': 'Vulnerability scanning',
        'ffuf': 'Directory busting',
        'subfinder': 'Subdomain enumeration',
        'assetfinder': 'Asset discovery',
        'wafw00f': 'WAF detection',
        'curl': 'HTTP requests',
        'dig': 'DNS queries',
    }
    
    OPTIONAL_TOOLS = {
        'testssl.sh': 'SSL/TLS analysis',
        'sqlmap': 'SQL injection testing',
        'cewl': 'Custom wordlist generation',
        'amass': 'Advanced subdomain enumeration',
        'masscan': 'Fast port scanning',
    }
    
    @staticmethod
    def check_command(cmd: str) -> bool:
        """Check if command is available in PATH"""
        result = subprocess.run(['which', cmd], capture_output=True)
        return result.returncode == 0
    
    @staticmethod
    def verify_tools() -> Tuple[List[str], List[str], List[str]]:
        """Return (installed_required, missing_required, missing_optional)"""
        installed_required = []
        missing_required = []
        missing_optional = []
        
        for tool in ToolChecker.REQUIRED_TOOLS:
            if ToolChecker.check_command(tool):
                installed_required.append(tool)
            else:
                missing_required.append(tool)
        
        for tool in ToolChecker.OPTIONAL_TOOLS:
            if not ToolChecker.check_command(tool):
                missing_optional.append(tool)
        
        return installed_required, missing_required, missing_optional


class Logger:
    """Advanced logging with colors and severity levels"""
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.log_file = output_dir / "assessment.log"
        
    def log(self, message: str, level: str = "INFO", verbose: bool = True):
        """Log with timestamp and severity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        color_map = {
            "INFO": Colors.OKBLUE,
            "SUCCESS": Colors.OKGREEN,
            "WARN": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "DEBUG": Colors.OKCYAN,
        }
        
        color = color_map.get(level, Colors.ENDC)
        formatted = f"{color}[{timestamp}] [{level}]{Colors.ENDC} {message}"
        
        if verbose:
            print(formatted)
        
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    
    def banner(self, text: str):
        """Print formatted banner"""
        print(f"\n{Colors.BOLD}{Colors.OKBLUE}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKBLUE}{text.center(70)}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKBLUE}{'='*70}{Colors.ENDC}\n")


class PenetrationTestingFramework:
    def __init__(self, target_url: str, output_dir: str = "webreporter_results", 
                 aggressive: bool = False, threads: int = 5, timeout: int = 300):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.aggressive = aggressive
        self.threads = threads
        self.timeout = timeout
        self.logger = Logger(self.output_dir)
        
        # Parse target
        self.parsed_url = urllib.parse.urlparse(target_url)
        self.domain = self.parsed_url.netloc or self.parsed_url.path
        self.host = self.domain.split(':')[0]
        self.protocol = self.parsed_url.scheme or 'https'
        
        self.results = {
            "metadata": {
                "target": target_url,
                "domain": self.domain,
                "host": self.host,
                "timestamp": datetime.now().isoformat(),
                "status": "in_progress",
                "aggressive_mode": aggressive
            },
            "scans": {},
            "vulnerabilities": [],
            "statistics": {}
        }
        
    def run_command(self, cmd: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
        """Execute command with error handling"""
        timeout = timeout or self.timeout
        try:
            self.logger.log(f"Executing: {' '.join(cmd)}", "DEBUG", verbose=False)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            self.logger.log(f"Command timeout: {cmd[0]}", "WARN")
            return {"success": False, "error": "Command timeout"}
        except FileNotFoundError:
            self.logger.log(f"Command not found: {cmd[0]}", "ERROR")
            return {"success": False, "error": f"Tool not installed: {cmd[0]}"}
        except Exception as e:
            self.logger.log(f"Command execution error: {str(e)}", "ERROR")
            return {"success": False, "error": str(e)}
    
    def subdomain_enumeration(self) -> Dict[str, Any]:
        """Advanced subdomain enumeration with multiple sources"""
        self.logger.log("🔍 Starting advanced subdomain enumeration...")
        scan_results = {
            "sources": {},
            "unique_subdomains": set(),
            "total_found": 0
        }
        
        # Subfinder
        if ToolChecker.check_command('subfinder'):
            self.logger.log("Scanning with subfinder...", "INFO")
            result = self.run_command(["subfinder", "-d", self.host, "-silent", "-all"])
            if result["success"]:
                subs = [s.strip() for s in result["stdout"].split('\n') if s.strip()]
                scan_results["sources"]["subfinder"] = len(subs)
                scan_results["unique_subdomains"].update(subs)
                self.logger.log(f"Found {len(subs)} subdomains via subfinder", "SUCCESS")
        
        # Assetfinder
        if ToolChecker.check_command('assetfinder'):
            self.logger.log("Scanning with assetfinder...", "INFO")
            result = self.run_command(["assetfinder", "--subs-only", self.host])
            if result["success"]:
                subs = [s.strip() for s in result["stdout"].split('\n') if s.strip()]
                scan_results["sources"]["assetfinder"] = len(subs)
                scan_results["unique_subdomains"].update(subs)
                self.logger.log(f"Found {len(subs)} subdomains via assetfinder", "SUCCESS")
        
        # Amass (if available)
        if ToolChecker.check_command('amass') and self.aggressive:
            self.logger.log("Running amass for deep enumeration...", "INFO")
            result = self.run_command(["amass", "enum", "-d", self.host, "-passive"], timeout=600)
            if result["success"]:
                subs = [s.strip() for s in result["stdout"].split('\n') if s.strip()]
                scan_results["sources"]["amass"] = len(subs)
                scan_results["unique_subdomains"].update(subs)
                self.logger.log(f"Found {len(subs)} subdomains via amass", "SUCCESS")
        
        # DNS enumeration
        self.logger.log("Performing DNS enumeration...", "INFO")
        dns_results = self.dns_enumeration()
        scan_results["dns_records"] = dns_results
        
        scan_results["unique_subdomains"] = list(scan_results["unique_subdomains"])
        scan_results["total_found"] = len(scan_results["unique_subdomains"])
        
        self.results["scans"]["subdomain_enumeration"] = scan_results
        self.logger.log(f"Total unique subdomains found: {scan_results['total_found']}", "SUCCESS")
        return scan_results
    
    def dns_enumeration(self) -> Dict[str, Any]:
        """Comprehensive DNS record enumeration"""
        dns_results = {
            "A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": [], "SOA": []
        }
        
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.host, rtype, lifetime=5)
                for rdata in answers:
                    dns_results[rtype].append(str(rdata))
            except Exception as e:
                self.logger.log(f"DNS {rtype} lookup failed: {str(e)}", "DEBUG", verbose=False)
        
        return dns_results
    
    def directory_busting(self) -> Dict[str, Any]:
        """Advanced directory and file enumeration"""
        self.logger.log("📂 Starting directory busting...")
        scan_results = {
            "results": [],
            "files_found": 0,
            "sensitive_findings": []
        }
        
        if not ToolChecker.check_command('ffuf'):
            self.logger.log("FFuf not installed, skipping directory busting", "WARN")
            return scan_results
        
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/small.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
        ]
        
        active_wordlist = None
        for wl in wordlists:
            if Path(wl).exists():
                active_wordlist = wl
                break
        
        if not active_wordlist:
            self.logger.log("No wordlists found for directory busting", "WARN")
            return scan_results
        
        output_file = self.output_dir / "ffuf_results.json"
        cmd = [
            "ffuf",
            "-u", f"{self.target_url}/FUZZ",
            "-w", active_wordlist,
            "-o", str(output_file),
            "-of", "json",
            "-fc", "404,403",
            "-ac"
        ]
        
        if self.aggressive:
            cmd.extend(["-t", str(self.threads * 2)])
        
        result = self.run_command(cmd, timeout=600)
        
        if result["success"]:
            try:
                with open(output_file, 'r') as f:
                    ffuf_data = json.load(f)
                    if 'results' in ffuf_data:
                        scan_results["files_found"] = len(ffuf_data['results'])
                        scan_results["results"] = ffuf_data['results'][:50]  # Top 50
                        
                        # Flag sensitive paths
                        sensitive_keywords = ['admin', 'config', 'backup', 'api', 'secret', 'private', 'internal']
                        for result_item in ffuf_data.get('results', []):
                            if any(kw in result_item.get('url', '').lower() for kw in sensitive_keywords):
                                scan_results["sensitive_findings"].append(result_item['url'])
            except Exception as e:
                self.logger.log(f"Error parsing ffuf results: {str(e)}", "WARN")
        else:
            self.logger.log(f"FFuf execution error: {result.get('error', 'Unknown')}", "WARN")
        
        self.results["scans"]["directory_busting"] = scan_results
        self.logger.log(f"Found {scan_results['files_found']} accessible paths", "SUCCESS")
        return scan_results
    
    def waf_detection(self) -> Dict[str, Any]:
        """WAF/IDS/IPS detection and fingerprinting"""
        self.logger.log("🛡️ Starting WAF detection and fingerprinting...")
        scan_results = {
            "wafw00f": None,
            "custom_detection": {},
            "detected": False
        }
        
        if ToolChecker.check_command('wafw00f'):
            result = self.run_command(["wafw00f", self.target_url, "-a"])
            if result["success"]:
                scan_results["wafw00f"] = result["stdout"]
                if "detected" in result["stdout"].lower():
                    scan_results["detected"] = True
                    self.logger.log("WAF detected!", "WARN")
        
        # Custom WAF signature detection
        try:
            headers_to_check = {
                'Server': None,
                'X-AspNet-Version': 'ASP.NET',
                'X-Powered-By': None,
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Type Sniffing Protection',
                'Content-Security-Policy': 'CSP Enabled'
            }
            
            resp = requests.head(self.target_url, timeout=10, allow_redirects=True)
            for header, indicator in headers_to_check.items():
                if header in resp.headers:
                    scan_results["custom_detection"][header] = resp.headers[header]
        except Exception as e:
            self.logger.log(f"Custom WAF detection error: {str(e)}", "DEBUG", verbose=False)
        
        self.results["scans"]["waf_detection"] = scan_results
        return scan_results
    
    def nuclei_scan(self) -> Dict[str, Any]:
        """Advanced Nuclei vulnerability scanning"""
        self.logger.log("🔬 Starting Nuclei vulnerability scan...")
        scan_results = {
            "executed": False,
            "vulnerabilities": [],
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        if not ToolChecker.check_command('nuclei'):
            self.logger.log("Nuclei not installed, skipping", "WARN")
            return scan_results
        
        output_file = self.output_dir / "nuclei_results.json"
        cmd = [
            "nuclei",
            "-u", self.target_url,
            "-json", "-o", str(output_file),
            "-rate-limit", "50"
        ]
        
        if self.aggressive:
            cmd.append("-duc")  # Update daily and use cache
        
        result = self.run_command(cmd, timeout=900)
        
        if result["success"]:
            scan_results["executed"] = True
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln = json.loads(line)
                            severity = vuln.get('info', {}).get('severity', 'unknown').lower()
                            
                            if severity == 'critical':
                                scan_results["critical"] += 1
                            elif severity == 'high':
                                scan_results["high"] += 1
                            elif severity == 'medium':
                                scan_results["medium"] += 1
                            elif severity == 'low':
                                scan_results["low"] += 1
                            
                            scan_results["vulnerabilities"].append({
                                "name": vuln.get('info', {}).get('name', 'Unknown'),
                                "severity": severity,
                                "template_id": vuln.get('template_id', 'N/A'),
                                "matched_at": vuln.get('matched_at', '')
                            })
            except Exception as e:
                self.logger.log(f"Error parsing nuclei results: {str(e)}", "WARN")
            
            total = sum([scan_results['critical'], scan_results['high'], 
                        scan_results['medium'], scan_results['low']])
            self.logger.log(f"Found {total} vulnerabilities (Critical: {scan_results['critical']}, "
                          f"High: {scan_results['high']}, Medium: {scan_results['medium']})", "SUCCESS")
        else:
            self.logger.log(f"Nuclei error: {result.get('error', 'Unknown')}", "WARN")
        
        self.results["scans"]["nuclei_scan"] = scan_results
        return scan_results
    
    def nmap_scans(self) -> Dict[str, Any]:
        """Comprehensive Nmap scanning"""
        self.logger.log("🎯 Starting Nmap reconnaissance...")
        scan_results = {
            "service_scan": {},
            "vulnerability_scan": {},
            "os_detection": {}
        }
        
        if not ToolChecker.check_command('nmap'):
            self.logger.log("Nmap not installed, skipping", "WARN")
            return scan_results
        
        # Service scan
        self.logger.log("Running service detection scan...", "INFO")
        output_xml = self.output_dir / "nmap_service.xml"
        output_txt = self.output_dir / "nmap_service.txt"
        cmd = [
            "nmap", "-sV", "-sC", "-p-" if self.aggressive else "-p1-10000",
            "-oX", str(output_xml),
            "-oN", str(output_txt),
            self.host
        ]
        
        result = self.run_command(cmd, timeout=600)
        scan_results["service_scan"]["executed"] = result["success"]
        if result["success"]:
            self.logger.log("Service scan completed", "SUCCESS")
        
        # Vulnerability scan
        if self.aggressive:
            self.logger.log("Running vulnerability script scan...", "INFO")
            vuln_xml = self.output_dir / "nmap_vuln.xml"
            vuln_txt = self.output_dir / "nmap_vuln.txt"
            cmd = [
                "nmap", "--script", "vuln,default",
                "-oX", str(vuln_xml),
                "-oN", str(vuln_txt),
                self.host
            ]
            
            result = self.run_command(cmd, timeout=900)
            scan_results["vulnerability_scan"]["executed"] = result["success"]
            if result["success"]:
                self.logger.log("Vulnerability scan completed", "SUCCESS")
        
        # OS detection
        self.logger.log("Running OS detection...", "INFO")
        os_xml = self.output_dir / "nmap_os.xml"
        cmd = [
            "nmap", "-O", "-oX", str(os_xml),
            self.host
        ]
        
        result = self.run_command(cmd, timeout=300)
        scan_results["os_detection"]["executed"] = result["success"]
        
        self.results["scans"]["nmap_scans"] = scan_results
        return scan_results
    
    def ssl_tls_analysis(self) -> Dict[str, Any]:
        """Advanced SSL/TLS security analysis"""
        self.logger.log("🔐 Starting SSL/TLS analysis...")
        scan_results = {
            "certificate_info": {},
            "protocols": {},
            "vulnerabilities": []
        }
        
        # Basic certificate inspection
        try:
            import ssl
            context = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    scan_results["certificate_info"] = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter')
                    }
                    
                    # Check self-signed
                    if scan_results["certificate_info"]["subject"] == scan_results["certificate_info"]["issuer"]:
                        scan_results["vulnerabilities"].append("Self-signed certificate")
        except Exception as e:
            self.logger.log(f"SSL inspection error: {str(e)}", "DEBUG", verbose=False)
        
        # testssl.sh if available
        if ToolChecker.check_command('testssl.sh'):
            self.logger.log("Running testssl.sh...", "INFO")
            output_file = self.output_dir / "testssl_results.json"
            cmd = [
                "testssl.sh",
                "--json", str(output_file),
                f"{self.protocol}://{self.domain}"
            ]
            
            result = self.run_command(cmd, timeout=600)
            if result["success"]:
                self.logger.log("testssl.sh completed", "SUCCESS")
        
        self.results["scans"]["ssl_tls_analysis"] = scan_results
        return scan_results
    
    def technology_fingerprinting(self) -> Dict[str, Any]:
        """Identify technologies, frameworks, and libraries"""
        self.logger.log("🔧 Starting technology fingerprinting...")
        scan_results = {
            "web_server": None,
            "frameworks": [],
            "cms": None,
            "programming_language": None,
            "javascript_libs": [],
            "headers": {}
        }
        
        try:
            resp = requests.get(self.target_url, timeout=10, allow_redirects=True)
            
            # Server detection
            if 'Server' in resp.headers:
                scan_results["web_server"] = resp.headers['Server']
            
            # Extract headers
            scan_results["headers"] = dict(resp.headers)
            
            # Content analysis
            content = resp.text.lower()
            
            # Framework detection
            frameworks = {
                'django': ['django', '/static/django'],
                'flask': ['flask', 'werkzeug'],
                'laravel': ['laravel', 'artisan'],
                'symfony': ['symfony', '_profiler'],
                'rails': ['rails', 'asset_path'],
                'spring': ['spring', 'j_spring'],
                'express': ['express', 'x-powered-by: express'],
                'next.js': ['__next', 'nextjs'],
                'react': ['react', 'reactroot'],
                'vue.js': ['vue', 'v-app'],
                'angular': ['angular', 'ng-app']
            }
            
            for framework, signatures in frameworks.items():
                if any(sig in content for sig in signatures):
                    scan_results["frameworks"].append(framework)
            
            # CMS detection
            cms_sigs = {
                'wordpress': ['wp-content', 'wp-includes'],
                'drupal': ['drupal', '/sites/'],
                'joomla': ['joomla', 'administrator'],
                'magento': ['magento', '/media/wysiwyg'],
                'shopify': ['cdn.shopify.com', 'shopify-enabled']
            }
            
            for cms, sigs in cms_sigs.items():
                if any(sig in content for sig in sigs):
                    scan_results["cms"] = cms
                    break
            
        except Exception as e:
            self.logger.log(f"Technology fingerprinting error: {str(e)}", "DEBUG", verbose=False)
        
        self.results["scans"]["technology_fingerprinting"] = scan_results
        self.logger.log(f"Identified technologies: {', '.join(scan_results['frameworks'] or ['Unknown'])}", "SUCCESS")
        return scan_results
    
    def security_headers_analysis(self) -> Dict[str, Any]:
        """Comprehensive security headers assessment"""
        self.logger.log("📋 Analyzing security headers...")
        scan_results = {
            "present": {},
            "missing": [],
            "score": 0,
            "recommendations": []
        }
        
        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'X-Frame-Options': 'Clickjacking protection',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'Browser XSS filter',
            'Referrer-Policy': 'Referrer leakage control',
            'Permissions-Policy': 'Feature permissions',
            'Set-Cookie': 'Secure flag check'
        }
        
        try:
            resp = requests.head(self.target_url, timeout=10, allow_redirects=True)
            
            for header, description in required_headers.items():
                if header in resp.headers:
                    scan_results["present"][header] = resp.headers[header]
                    scan_results["score"] += 1
                else:
                    scan_results["missing"].append(header)
                    scan_results["recommendations"].append(f"Add {header} header")
            
            scan_results["score"] = int((scan_results["score"] / len(required_headers)) * 100)
            
        except Exception as e:
            self.logger.log(f"Headers analysis error: {str(e)}", "DEBUG", verbose=False)
        
        self.results["scans"]["security_headers"] = scan_results
        self.logger.log(f"Security headers score: {scan_results['score']}/100", "SUCCESS")
        return scan_results
    
    def api_endpoint_discovery(self) -> Dict[str, Any]:
        """Discover and analyze API endpoints"""
        self.logger.log("🔌 Discovering API endpoints...")
        scan_results = {
            "endpoints": [],
            "api_versions": set(),
            "documentation": []
        }
        
        api_patterns = [
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
            '/swagger', '/api-docs', '/openapi', '/webhook', '/rpc'
        ]
        
        try:
            for pattern in api_patterns:
                test_urls = [
                    f"{self.target_url}{pattern}",
                    f"{self.target_url}{pattern}docs",
                    f"{self.target_url}{pattern.replace('/', '')}"
                ]
                
                for url in test_urls:
                    try:
                        resp = requests.head(url, timeout=5, allow_redirects=True)
                        if resp.status_code < 400:
                            scan_results["endpoints"].append(url)
                            if any(v in pattern for v in ['v1', 'v2', 'v3']):
                                scan_results["api_versions"].add(pattern)
                    except:
                        pass
        except Exception as e:
            self.logger.log(f"API discovery error: {str(e)}", "DEBUG", verbose=False)
        
        scan_results["api_versions"] = list(scan_results["api_versions"])
        self.results["scans"]["api_discovery"] = scan_results
        self.logger.log(f"Found {len(scan_results['endpoints'])} potential API endpoints", "SUCCESS")
        return scan_results
    
    def generate_comprehensive_report(self):
        """Generate professional HTML report with visualizations"""
        self.logger.log("📊 Generating comprehensive report...")
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebReporter - Penetration Test Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            padding: 20px;
        }}
        .container {{ 
            max-width: 1400px; margin: 0 auto; 
            background: white; 
            border-radius: 10px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 40px; 
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        .metadata {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            padding: 30px; 
            background: #f8f9fa;
        }}
        .meta-item {{ 
            background: white; 
            padding: 15px; 
            border-radius: 8px; 
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .meta-item strong {{ color: #667eea; }}
        .content {{ padding: 40px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ 
            color: #667eea; 
            border-bottom: 3px solid #667eea; 
            padding-bottom: 15px; 
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        .vulnerability {{ 
            background: white; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 8px;
            border-left: 5px solid #d32f2f;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .vulnerability.high {{ border-left-color: #ff5252; }}
        .vulnerability.medium {{ border-left-color: #ffa726; }}
        .vulnerability.low {{ border-left-color: #66bb6a; }}
        .score-box {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; 
            padding: 20px; 
            border-radius: 8px; 
            text-align: center; 
            font-size: 2em; 
            font-weight: bold;
            margin: 20px 0;
        }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .chart-container {{ position: relative; height: 300px; margin: 20px 0; }}
        .footer {{ 
            background: #f8f9fa; 
            padding: 30px; 
            text-align: center; 
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #666;
        }}
        .warning-box {{ 
            background: #fff3cd; 
            border-left: 4px solid #ffc107; 
            padding: 15px; 
            margin: 20px 0;
            border-radius: 4px;
        }}
        .success {{ color: #66bb6a; font-weight: bold; }}
        .danger {{ color: #d32f2f; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WebReporter - Penetration Test Report</h1>
            <p>Professional Security Assessment</p>
        </div>
        
        <div class="metadata">
            <div class="meta-item">
                <strong>Target:</strong><br>{self.results['metadata']['target']}
            </div>
            <div class="meta-item">
                <strong>Domain:</strong><br>{self.results['metadata']['domain']}
            </div>
            <div class="meta-item">
                <strong>Scan Date:</strong><br>{self.results['metadata']['timestamp'].split('T')[0]}
            </div>
            <div class="meta-item">
                <strong>Mode:</strong><br>{'Aggressive' if self.aggressive else 'Standard'}
            </div>
        </div>
        
        <div class="content">
            <div class="warning-box">
                <strong>⚠️ Legal Disclaimer:</strong> This report is for authorized penetration testing only. 
                Unauthorized security testing is illegal. All activities were conducted with proper authorization.
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="grid-2">
                    <div>
                        <h3>Vulnerability Summary</h3>
                        <table>
                            <tr>
                                <td><strong>Critical:</strong></td>
                                <td class="danger">{self.results['scans'].get('nuclei_scan', {}).get('critical', 0)}</td>
                            </tr>
                            <tr>
                                <td><strong>High:</strong></td>
                                <td class="danger">{self.results['scans'].get('nuclei_scan', {}).get('high', 0)}</td>
                            </tr>
                            <tr>
                                <td><strong>Medium:</strong></td>
                                <td>{self.results['scans'].get('nuclei_scan', {}).get('medium', 0)}</td>
                            </tr>
                            <tr>
                                <td><strong>Low:</strong></td>
                                <td class="success">{self.results['scans'].get('nuclei_scan', {}).get('low', 0)}</td>
                            </tr>
                        </table>
                    </div>
                    <div>
                        <h3>Security Posture</h3>
                        <div class="score-box">
                            {self.results['scans'].get('security_headers', {}).get('score', 0)}%
                        </div>
                        <p style="text-align: center;">Security Headers Score</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Subdomain Enumeration</h2>
                <p><strong>Total Subdomains Found:</strong> {self.results['scans'].get('subdomain_enumeration', {}).get('total_found', 0)}</p>
                <details>
                    <summary style="cursor: pointer; padding: 10px; background: #f0f0f0; border-radius: 4px;">View Subdomains</summary>
                    <ul style="margin-top: 10px;">
"""
        
        subdomains = self.results['scans'].get('subdomain_enumeration', {}).get('unique_subdomains', [])
        for sub in subdomains[:20]:  # Show first 20
            html += f"<li>{sub}</li>\n"
        
        if len(subdomains) > 20:
            html += f"<li><em>... and {len(subdomains) - 20} more</em></li>\n"
        
        html += """
                    </ul>
                </details>
            </div>
            
            <div class="section">
                <h2>📂 Directory Findings</h2>
"""
        dir_results = self.results['scans'].get('directory_busting', {})
        html += f"<p><strong>Accessible Paths Found:</strong> {dir_results.get('files_found', 0)}</p>"
        
        if dir_results.get('sensitive_findings'):
            html += "<h3 style='color: #d32f2f;'>🚨 Sensitive Paths Detected:</h3><ul>"
            for finding in dir_results.get('sensitive_findings', [])[:10]:
                html += f"<li>{finding}</li>\n"
            html += "</ul>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>🛡️ WAF Detection</h2>
"""
        waf = self.results['scans'].get('waf_detection', {})
        if waf.get('detected'):
            html += "<p class='danger'>⚠️ WAF/IDS detected - Adjust testing methodology</p>"
        else:
            html += "<p class='success'>✓ No WAF detected</p>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>🔧 Technology Stack</h2>
"""
        tech = self.results['scans'].get('technology_fingerprinting', {})
        html += f"<p><strong>Web Server:</strong> {tech.get('web_server', 'Unknown')}</p>"
        if tech.get('frameworks'):
            html += f"<p><strong>Frameworks:</strong> {', '.join(tech.get('frameworks', []))}</p>"
        if tech.get('cms'):
            html += f"<p><strong>CMS:</strong> {tech.get('cms')}</p>"
        
        html += """
            </div>
            
            <div class="section">
                <h2>📋 Security Headers</h2>
"""
        headers = self.results['scans'].get('security_headers', {})
        html += f"<p><strong>Score: </strong>{headers.get('score', 0)}/100</p>"
        
        if headers.get('present'):
            html += "<h3>✓ Present Headers:</h3><ul>"
            for header in headers.get('present', {}).keys():
                html += f"<li>{header}</li>\n"
            html += "</ul>"
        
        if headers.get('missing'):
            html += "<h3 style='color: #ff6b6b;'>✗ Missing Headers:</h3><ul>"
            for header in headers.get('missing', []):
                html += f"<li>{header}</li>\n"
            html += "</ul>"
        
        html += f"""
            </div>
            
            <div class="section">
                <h2>🔐 SSL/TLS Analysis</h2>
"""
        ssl = self.results['scans'].get('ssl_tls_analysis', {})
        if ssl.get('vulnerabilities'):
            html += "<p style='color: #ff6b6b;'><strong>Issues Found:</strong></p><ul>"
            for vuln in ssl.get('vulnerabilities', []):
                html += f"<li>{vuln}</li>\n"
            html += "</ul>"
        else:
            html += "<p class='success'>✓ No major SSL/TLS issues detected</p>"
        
        html += f"""
            </div>
            
            <div class="footer">
                <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>WebReporter v1.0 | Professional Penetration Testing Framework</p>
                <p>For authorized security testing only. Unauthorized access to computer systems is illegal.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        report_path = self.output_dir / "report.html"
        with open(report_path, "w") as f:
            f.write(html)
        
        self.logger.log(f"HTML report generated: {report_path}", "SUCCESS")
        return report_path
    
    def run_full_assessment(self):
        """Execute complete assessment"""
        self.logger.banner("WEBREPORTER - PENETRATION TESTING FRAMEWORK")
        
        # Check tools
        installed, missing, optional = ToolChecker.verify_tools()
        self.logger.log(f"Tools available: {len(installed)}/{len(ToolChecker.REQUIRED_TOOLS)}", "INFO")
        
        if missing:
            self.logger.log(f"Missing tools: {', '.join(missing)}", "WARN")
            self.logger.log("Some scans will be skipped. Install missing tools for full assessment.", "WARN")
        
        try:
            start_time = time.time()
            
            self.subdomain_enumeration()
            self.directory_busting()
            self.waf_detection()
            self.nuclei_scan()
            self.nmap_scans()
            self.ssl_tls_analysis()
            self.technology_fingerprinting()
            self.security_headers_analysis()
            self.api_endpoint_discovery()
            
            elapsed = time.time() - start_time
            self.results["metadata"]["status"] = "completed"
            self.results["metadata"]["duration_seconds"] = round(elapsed, 2)
            
            # Save results
            json_path = self.output_dir / "results.json"
            with open(json_path, "w") as f:
                json.dump(self.results, f, indent=2, default=str)
            
            self.generate_comprehensive_report()
            
            self.logger.banner("ASSESSMENT COMPLETE")
            self.logger.log(f"Duration: {elapsed:.2f} seconds", "SUCCESS")
            self.logger.log(f"Results saved to: {self.output_dir}", "SUCCESS")
            
        except KeyboardInterrupt:
            self.logger.log("Assessment interrupted by user", "WARN")
            sys.exit(0)
        except Exception as e:
            self.logger.log(f"Critical error: {str(e)}", "ERROR")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}WebReporter{Colors.ENDC} - Advanced Professional Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.BOLD}EXAMPLES:{Colors.ENDC}
  python3 webreporter.py -u https://example.com
  python3 webreporter.py -u https://example.com -a -t 10
  python3 webreporter.py -u https://target.com -o results_2024/

{Colors.BOLD}LEGAL NOTICE:{Colors.ENDC}
  This tool is for AUTHORIZED penetration testing only.
  Unauthorized access to computer systems is ILLEGAL.
  Always obtain written permission before testing.

{Colors.BOLD}FEATURES:{Colors.ENDC}
  ✓ Subdomain enumeration (multiple sources)
  ✓ Directory and file discovery
  ✓ WAF/IDS/IPS detection
  ✓ Vulnerability scanning (Nuclei)
  ✓ Network reconnaissance (Nmap)
  ✓ SSL/TLS analysis
  ✓ Technology fingerprinting
  ✓ Security headers assessment
  ✓ API endpoint discovery
  ✓ DNS enumeration
  ✓ Professional HTML reporting
        """
    )
    
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (e.g., https://example.com)",
        metavar="URL"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="webreporter_results",
        help="Output directory (default: webreporter_results)",
        metavar="DIR"
    )
    
    parser.add_argument(
        "-a", "--aggressive",
        action="store_true",
        help="Enable aggressive scanning mode (slower but more thorough)"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=5,
        help="Number of threads (default: 5)",
        metavar="N"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout for commands in seconds (default: 300)",
        metavar="SECONDS"
    )
    
    args = parser.parse_args()
    
    framework = PenetrationTestingFramework(
        args.url,
        args.output,
        aggressive=args.aggressive,
        threads=args.threads,
        timeout=args.timeout
    )
    
    framework.run_full_assessment()


if __name__ == "__main__":
    main()
