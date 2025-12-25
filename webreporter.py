#!/usr/bin/env python3
"""
Professional Penetration Testing Framework
Comprehensive security assessment tool for authorized testing only
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import urllib.parse

class PenetrationTestingFramework:
    def __init__(self, target_url: str, output_dir: str = "pentest_results"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {
            "metadata": {
                "target": target_url,
                "timestamp": datetime.now().isoformat(),
                "status": "in_progress"
            },
            "scans": {}
        }
        self.vulnerabilities = []
        
    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def run_command(self, cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute a system command and capture output"""
        try:
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
            return {"success": False, "error": "Command timeout"}
        except FileNotFoundError:
            return {"success": False, "error": f"Command not found: {cmd[0]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def subdomain_enumeration(self):
        """Subdomain enumeration using multiple methods"""
        self.log("Starting subdomain enumeration...")
        scan_results = {}
        
        # Extract domain from URL
        parsed = urllib.parse.urlparse(self.target_url)
        domain = parsed.netloc or parsed.path
        
        # Method 1: Using subfinder (if available)
        self.log(f"Attempting subdomain enumeration with subfinder...")
        result = self.run_command(["subfinder", "-d", domain, "-silent"])
        if result["success"]:
            subdomains = result["stdout"].strip().split("\n")
            scan_results["subfinder"] = [s for s in subdomains if s]
            self.log(f"Found {len(scan_results['subfinder'])} subdomains via subfinder")
        
        # Method 2: Using assetfinder
        self.log(f"Attempting subdomain enumeration with assetfinder...")
        result = self.run_command(["assetfinder", "--subs-only", domain])
        if result["success"]:
            subdomains = result["stdout"].strip().split("\n")
            scan_results["assetfinder"] = [s for s in subdomains if s]
            self.log(f"Found {len(scan_results['assetfinder'])} subdomains via assetfinder")
        
        self.results["scans"]["subdomain_enumeration"] = scan_results
        return scan_results
        
    def directory_busting(self):
        """Directory and file enumeration"""
        self.log("Starting directory busting...")
        scan_results = {}
        
        # Using ffuf if available
        self.log("Attempting directory enumeration with ffuf...")
        cmd = [
            "ffuf",
            "-u", f"{self.target_url}/FUZZ",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-o", str(self.output_dir / "ffuf_results.json"),
            "-of", "json",
            "-fc", "404"
        ]
        result = self.run_command(cmd, timeout=600)
        scan_results["ffuf"] = {
            "executed": result["success"],
            "output_file": "ffuf_results.json" if result["success"] else None
        }
        
        if result["success"]:
            self.log("Directory busting completed")
        else:
            self.log(f"FFuf error: {result.get('error', 'Unknown error')}", "WARN")
        
        self.results["scans"]["directory_busting"] = scan_results
        return scan_results
        
    def waf_detection(self):
        """WAF detection and analysis"""
        self.log("Starting WAF detection...")
        scan_results = {}
        
        # Using wafw00f
        self.log("Analyzing WAF with wafw00f...")
        result = self.run_command([
            "wafw00f",
            self.target_url,
            "-o", str(self.output_dir / "wafw00f_results.txt")
        ])
        
        scan_results["wafw00f"] = {
            "executed": result["success"],
            "output": result["stdout"] if result["success"] else result["error"]
        }
        
        self.log("WAF detection completed")
        self.results["scans"]["waf_detection"] = scan_results
        return scan_results
        
    def nuclei_scan(self):
        """Nuclei vulnerability scanning"""
        self.log("Starting Nuclei vulnerability scan...")
        scan_results = {}
        
        self.log("Running nuclei for vulnerability detection...")
        cmd = [
            "nuclei",
            "-u", self.target_url,
            "-j", "-o", str(self.output_dir / "nuclei_results.json")
        ]
        result = self.run_command(cmd, timeout=900)
        
        scan_results["nuclei"] = {
            "executed": result["success"],
            "output_file": "nuclei_results.json" if result["success"] else None
        }
        
        if result["success"]:
            self.log("Nuclei scan completed")
        else:
            self.log(f"Nuclei error: {result.get('error', 'Unknown error')}", "WARN")
        
        self.results["scans"]["nuclei_scan"] = scan_results
        return scan_results
        
    def nmap_scan(self):
        """Nmap network scanning"""
        self.log("Starting Nmap scan...")
        scan_results = {}
        
        parsed = urllib.parse.urlparse(self.target_url)
        host = parsed.netloc or parsed.path
        
        # Standard service scan
        self.log("Running standard port/service scan...")
        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "-oX", str(self.output_dir / "nmap_scan.xml"),
            "-oN", str(self.output_dir / "nmap_scan.txt"),
            host
        ]
        result = self.run_command(cmd, timeout=600)
        scan_results["service_scan"] = {
            "executed": result["success"],
            "output_files": ["nmap_scan.xml", "nmap_scan.txt"] if result["success"] else None
        }
        
        if result["success"]:
            self.log("Nmap service scan completed")
        else:
            self.log(f"Nmap error: {result.get('error', 'Unknown error')}", "WARN")
        
        self.results["scans"]["nmap_scan"] = scan_results
        return scan_results
        
    def nmap_vuln_scan(self):
        """Nmap vulnerability script scanning"""
        self.log("Starting Nmap vulnerability scan...")
        scan_results = {}
        
        parsed = urllib.parse.urlparse(self.target_url)
        host = parsed.netloc or parsed.path
        
        self.log("Running Nmap NSE vulnerability scripts...")
        cmd = [
            "nmap",
            "--script", "vuln",
            "-oX", str(self.output_dir / "nmap_vuln_scan.xml"),
            "-oN", str(self.output_dir / "nmap_vuln_scan.txt"),
            host
        ]
        result = self.run_command(cmd, timeout=900)
        scan_results["vuln_scripts"] = {
            "executed": result["success"],
            "output_files": ["nmap_vuln_scan.xml", "nmap_vuln_scan.txt"] if result["success"] else None
        }
        
        if result["success"]:
            self.log("Nmap vulnerability scan completed")
        else:
            self.log(f"Nmap vuln scan error: {result.get('error', 'Unknown error')}", "WARN")
        
        self.results["scans"]["nmap_vuln_scan"] = scan_results
        return scan_results
        
    def ssl_tls_scan(self):
        """SSL/TLS security analysis"""
        self.log("Starting SSL/TLS security scan...")
        scan_results = {}
        
        parsed = urllib.parse.urlparse(self.target_url)
        host = parsed.netloc or parsed.path
        
        # Using testssl.sh if available
        self.log("Analyzing SSL/TLS with testssl...")
        cmd = [
            "testssl.sh",
            "--json", str(self.output_dir / "testssl_results.json"),
            f"https://{host}"
        ]
        result = self.run_command(cmd, timeout=600)
        scan_results["testssl"] = {
            "executed": result["success"],
            "output_file": "testssl_results.json" if result["success"] else None
        }
        
        self.results["scans"]["ssl_tls_scan"] = scan_results
        return scan_results
        
    def http_header_analysis(self):
        """Analyze HTTP security headers"""
        self.log("Starting HTTP header analysis...")
        scan_results = {}
        
        try:
            import requests
            response = requests.head(self.target_url, timeout=10, allow_redirects=True)
            headers = dict(response.headers)
            
            security_headers = [
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
                "X-XSS-Protection"
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            
            scan_results["headers_found"] = headers
            scan_results["missing_security_headers"] = missing_headers
            
            if missing_headers:
                self.log(f"Missing security headers: {', '.join(missing_headers)}", "WARN")
            
        except Exception as e:
            scan_results["error"] = str(e)
            self.log(f"HTTP header analysis error: {e}", "WARN")
        
        self.results["scans"]["http_header_analysis"] = scan_results
        return scan_results
        
    def generate_report(self):
        """Generate comprehensive HTML report"""
        self.log("Generating comprehensive report...")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; border-left: 5px solid #2196F3; padding-left: 15px; }}
        .metadata {{ background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .metadata p {{ margin: 8px 0; }}
        .scan-section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .status-success {{ color: #4CAF50; font-weight: bold; }}
        .status-warning {{ color: #ff9800; font-weight: bold; }}
        .status-error {{ color: #d32f2f; font-weight: bold; }}
        .scan-result {{ background: #fafafa; padding: 10px; margin: 10px 0; border-left: 4px solid #2196F3; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #2196F3; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Penetration Test Report</h1>
        
        <div class="metadata">
            <p><strong>Target:</strong> {self.results['metadata']['target']}</p>
            <p><strong>Scan Date:</strong> {self.results['metadata']['timestamp']}</p>
            <p><strong>Status:</strong> <span class="status-success">Completed</span></p>
        </div>
        
        <h2>Scan Summary</h2>
        <p>Total scans executed: {len(self.results['scans'])}</p>
        
        <h2>Detailed Results</h2>
"""
        
        for scan_name, scan_data in self.results['scans'].items():
            html_content += f"""
        <div class="scan-section">
            <h3>{scan_name.replace('_', ' ').title()}</h3>
            <pre>{json.dumps(scan_data, indent=2)}</pre>
        </div>
"""
        
        html_content += """
        <div class="footer">
            <p><strong>Disclaimer:</strong> This report is for authorized penetration testing only.</p>
            <p>All testing was conducted with proper authorization. Unauthorized testing is illegal.</p>
        </div>
    </div>
</body>
</html>
"""
        
        report_path = self.output_dir / "report.html"
        with open(report_path, "w") as f:
            f.write(html_content)
        
        self.log(f"Report generated: {report_path}")
        return report_path
        
    def run_full_assessment(self):
        """Execute complete penetration testing assessment"""
        self.log("=" * 60)
        self.log("PENETRATION TESTING FRAMEWORK - AUTHORIZED TESTING ONLY")
        self.log("=" * 60)
        
        try:
            self.subdomain_enumeration()
            self.directory_busting()
            self.waf_detection()
            self.nuclei_scan()
            self.nmap_scan()
            self.nmap_vuln_scan()
            self.ssl_tls_scan()
            self.http_header_analysis()
            
            self.results["metadata"]["status"] = "completed"
            
            # Save JSON results
            json_path = self.output_dir / "results.json"
            with open(json_path, "w") as f:
                json.dump(self.results, f, indent=2)
            
            self.log(f"JSON results saved: {json_path}")
            self.generate_report()
            
            self.log("=" * 60)
            self.log("ASSESSMENT COMPLETE")
            self.log(f"Results directory: {self.output_dir}")
            self.log("=" * 60)
            
        except KeyboardInterrupt:
            self.log("Assessment interrupted by user", "WARN")
            sys.exit(0)
        except Exception as e:
            self.log(f"Assessment error: {e}", "ERROR")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Professional Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IMPORTANT: This tool is designed for authorized security testing only.
Unauthorized testing is illegal. Always obtain written permission before testing.

Example usage:
  python3 pentest_tool.py -u https://example.com
  python3 pentest_tool.py -u https://example.com -o custom_results/
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL to test")
    parser.add_argument("-o", "--output", default="pentest_results", help="Output directory for results")
    
    args = parser.parse_args()
    
    framework = PenetrationTestingFramework(args.url, args.output)
    framework.run_full_assessment()


if __name__ == "__main__":
    main()
