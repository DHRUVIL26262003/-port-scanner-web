#!/usr/bin/env python3
"""
Web-based Port Scanner Application
A Flask web interface for scanning any website's open ports
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
import socket
import threading
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urlparse
import re
import os

app = Flask(__name__)

# Global variables for scan results
scan_results = {}
scan_progress = {}

class WebPortScanner:
    def __init__(self, target, scan_id):
        self.target = target
        self.scan_id = scan_id
        self.open_ports = []
        self.services = {}
        self.banners = {}
        self.web_info = {}
        
        # Common ports and their services
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
            1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9000: "HTTP-Alt", 3000: "HTTP-Alt",
            5000: "HTTP-Alt", 8000: "HTTP-Alt", 8001: "HTTP-Alt", 8008: "HTTP-Alt",
            8081: "HTTP-Alt", 8082: "HTTP-Alt", 8083: "HTTP-Alt", 8084: "HTTP-Alt",
            8085: "HTTP-Alt", 8086: "HTTP-Alt", 8087: "HTTP-Alt", 8088: "HTTP-Alt",
            8089: "HTTP-Alt", 8090: "HTTP-Alt", 9090: "HTTP-Alt", 9443: "HTTPS-Alt",
            9999: "HTTP-Alt", 10000: "HTTP-Alt"
        }

    def resolve_target(self):
        """Resolve target to IP address if it's a domain"""
        try:
            # Extract domain from URL if needed
            if self.target.startswith(('http://', 'https://')):
                parsed = urlparse(self.target)
                domain = parsed.hostname
            else:
                domain = self.target
            
            if not domain.replace('.', '').isdigit():
                ip = socket.gethostbyname(domain)
                return ip, domain
            return domain, domain
        except socket.gaierror:
            return None, None

    def scan_port(self, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def grab_banner(self, port):
        """Attempt to grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner if banner else None
        except:
            return None

    def scan_ports(self, ports=None, threads=50):
        """Scan specified ports"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        total_ports = len(ports)
        scanned = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                scanned += 1
                
                # Update progress
                progress = int((scanned / total_ports) * 100)
                scan_progress[self.scan_id] = {
                    'progress': progress,
                    'scanned': scanned,
                    'total': total_ports,
                    'open_ports': len(self.open_ports)
                }
                
                try:
                    result = future.result()
                    if result:
                        self.open_ports.append(port)
                        service = self.common_ports.get(port, "Unknown")
                        self.services[port] = service
                        
                        # Try to grab banner
                        banner = self.grab_banner(port)
                        if banner:
                            self.banners[port] = banner
                            
                except Exception as e:
                    pass

    def web_enumeration(self):
        """Perform web enumeration on open web ports"""
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 9090, 9443, 9999, 10000]
        open_web_ports = [port for port in self.open_ports if port in web_ports]
        
        for port in open_web_ports:
            protocol = "https" if port in [443, 8443, 9443] else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                self.web_info[port] = {
                    'url': url,
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'title': self.extract_title(response.text),
                    'content_length': len(response.content)
                }
            except Exception as e:
                self.web_info[port] = {
                    'url': url,
                    'error': str(e)
                }

    def extract_title(self, html):
        """Extract page title from HTML"""
        try:
            title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return "No title found"

    def run_scan(self):
        """Run the complete scan"""
        start_time = time.time()
        
        # Resolve target
        ip, domain = self.resolve_target()
        if not ip:
            return {'error': f'Could not resolve {self.target}'}
        
        self.target = ip
        
        # Scan ports
        self.scan_ports()
        
        # Web enumeration
        if self.open_ports:
            self.web_enumeration()
        
        end_time = time.time()
        
        # Store results
        results = {
            'target': self.target,
            'domain': domain,
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'duration': round(end_time - start_time, 2),
            'open_ports': sorted(self.open_ports),
            'services': self.services,
            'banners': self.banners,
            'web_info': self.web_info,
            'summary': {
                'total_open_ports': len(self.open_ports),
                'common_services': [port for port in self.open_ports if port in self.common_ports],
                'unknown_services': [port for port in self.open_ports if port not in self.common_ports]
            }
        }
        
        scan_results[self.scan_id] = results
        return results

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json()
    target = data.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Please provide a target website'}), 400
    
    # Generate unique scan ID
    scan_id = f"scan_{int(time.time())}"
    
    # Start scan in background thread
    def run_scan():
        scanner = WebPortScanner(target, scan_id)
        scanner.run_scan()
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    # Initialize progress
    scan_progress[scan_id] = {
        'progress': 0,
        'scanned': 0,
        'total': len(WebPortScanner('', '').common_ports),
        'open_ports': 0
    }
    
    return jsonify({'scan_id': scan_id})

@app.route('/progress/<scan_id>')
def get_progress(scan_id):
    """Get scan progress"""
    if scan_id in scan_progress:
        return jsonify(scan_progress[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/results/<scan_id>')
def get_results(scan_id):
    """Get scan results"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Results not found'}), 404

@app.route('/results/<scan_id>/page')
def results_page(scan_id):
    """Results page"""
    if scan_id not in scan_results:
        return "Scan results not found", 404
    return render_template('results.html', scan_id=scan_id)

# Production configuration
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
