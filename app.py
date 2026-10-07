import os
import sys
import json
import signal
import threading
import time
import socket
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from flask import Flask, render_template, jsonify, request

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
    SCAVAILABLE = True
except ImportError:
    SCAVAILABLE = False
    print("Warning: scapy not installed. Packet capture disabled. Install with: pip install scapy")

BASE_DIR = Path(__file__).parent
REPORT_FILE = BASE_DIR / 'report.html'
DB_FILE = BASE_DIR / 'monitor.db'

app = Flask(__name__)

# Global state
capture_thread = None
capture_running = False
packet_lock = threading.Lock()

# Statistics
stats = {
    'total_packets': 0,
    'allowed': 0,
    'blocked': 0,
    'top_ports': Counter(),
    'top_ips': Counter(),
    'top_domains': Counter(),
    'protocols': Counter(),
    'start_time': None,
    'end_time': None
}

# DNS cache
dns_cache = {}

def resolve_dns(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        dns_cache[ip] = hostname
        return hostname
    except:
        dns_cache[ip] = ip
        return ip

def classify_packet(pkt):
    """Simple classification - in real use, integrate with firewall rules"""
    if IP in pkt:
        ip = pkt[IP]
        dst_port = None
        if TCP in pkt:
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
        
        # Example rules: block common attack ports
        blocked_ports = {23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900}
        if dst_port in blocked_ports:
            return 'blocked'
    return 'allowed'

def process_packet(pkt):
    global stats
    if IP not in pkt:
        return
    
    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto
    
    with packet_lock:
        stats['total_packets'] += 1
        
        # Protocol tracking
        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
        stats['protocols'][proto_name] += 1
        
        # IP tracking
        stats['top_ips'][src_ip] += 1
        stats['top_ips'][dst_ip] += 1
        
        # Port tracking
        dst_port = None
        if TCP in pkt:
            dst_port = pkt[TCP].dport
            stats['top_ports'][dst_port] += 1
        elif UDP in pkt:
            dst_port = pkt[UDP].dport
            stats['top_ports'][dst_port] += 1
        
        # Classification
        verdict = classify_packet(pkt)
        if verdict == 'blocked':
            stats['blocked'] += 1
        else:
            stats['allowed'] += 1
        
        # DNS tracking
        if DNS in pkt and DNSQR in pkt:
            try:
                domain = pkt[DNSQR].qname.decode().rstrip('.')
                stats['top_domains'][domain] += 1
            except:
                pass

def capture_worker(interface=None, filter_str=None):
    global capture_running
    if not SCAVAILABLE:
        print("Scapy not available, capture worker exiting")
        capture_running = False
        return
    
    try:
        sniff(
            iface=interface,
            filter=filter_str,
            prn=process_packet,
            store=False,
            stop_filter=lambda x: not capture_running
        )
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        capture_running = False

def start_capture(interface=None, filter_str="ip"):
    global capture_thread, capture_running, stats
    if capture_running:
        return False
    
    stats = {
        'total_packets': 0,
        'allowed': 0,
        'blocked': 0,
        'top_ports': Counter(),
        'top_ips': Counter(),
        'top_domains': Counter(),
        'protocols': Counter(),
        'start_time': datetime.now().isoformat(),
        'end_time': None
    }
    
    capture_running = True
    capture_thread = threading.Thread(target=capture_worker, args=(interface, filter_str), daemon=True)
    capture_thread.start()
    return True

def stop_capture():
    global capture_running, capture_thread
    capture_running = False
    if capture_thread:
        capture_thread.join(timeout=5)
    stats['end_time'] = datetime.now().isoformat()
    generate_report()

def generate_report():
    """Generate HTML report on stop"""
    
    # Prepare data
    top_ports = stats['top_ports'].most_common(20)
    top_ips = stats['top_ips'].most_common(20)
    top_domains = stats['top_domains'].most_common(20)
    
    # Resolve IPs for report
    ip_data = []
    for ip, count in top_ips:
        domain = resolve_dns(ip)
        ip_data.append({'ip': ip, 'domain': domain, 'count': count})
    
    port_data = [{'port': p, 'count': c, 'service': get_service_name(p)} for p, c in top_ports]
    domain_data = [{'domain': d, 'count': c} for d, c in top_domains]
    
    duration = 0
    if stats['start_time'] and stats['end_time']:
        try:
            start = datetime.fromisoformat(stats['start_time'])
            end = datetime.fromisoformat(stats['end_time'])
            duration = (end - start).total_seconds()
        except:
            pass
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Monitor Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 36px; font-weight: bold; color: #333; }}
        .stat-label {{ color: #666; font-size: 14px; margin-top: 4px; }}
        .stat-allowed {{ color: #28a745; }}
        .stat-blocked {{ color: #dc3545; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #333; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
        .badge-allowed {{ background: #d4edda; color: #155724; }}
        .badge-blocked {{ background: #f8d7da; color: #721c24; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #333; border-bottom: 1px solid #e9ecef; padding-bottom: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Monitor Report</h1>
        <div class="meta">
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            Capture Duration: {duration:.0f} seconds<br>
            Start: {stats['start_time'] or 'N/A'}<br>
            End: {stats['end_time'] or 'N/A'}
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total_packets']}</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-allowed">{stats['allowed']}</div>
                <div class="stat-label">Allowed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value stat-blocked">{stats['blocked']}</div>
                <div class="stat-label">Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(stats['top_ips'])}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Protocols</h2>
            <table>
                <tr><th>Protocol</th><th>Packets</th></tr>
                {''.join(f'<tr><td>{p}</td><td>{c}</td></tr>' for p, c in stats['protocols'].most_common())}
            </table>
        </div>
        
        <div class="section">
            <h2>Top Ports</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Packets</th></tr>
                {''.join(f'<tr><td>{p["port"]}</td><td>{p["service"]}</td><td>{p["count"]}</td></tr>' for p in port_data)}
            </table>
        </div>
        
        <div class="section">
            <h2>Top IP Addresses</h2>
            <table>
                <tr><th>IP</th><th>Domain</th><th>Packets</th></tr>
                {''.join(f'<tr><td>{i["ip"]}</td><td>{i["domain"]}</td><td>{i["count"]}</td></tr>' for i in ip_data)}
            </table>
        </div>
        
        <div class="section">
            <h2>Top Domains (DNS)</h2>
            <table>
                <tr><th>Domain</th><th>Queries</th></tr>
                {''.join(f'<tr><td>{d["domain"]}</td><td>{d["count"]}</td></tr>' for d in domain_data)}
            </table>
        </div>
    </div>
</body>
</html>"""
    
    with open(REPORT_FILE, 'w') as f:
        f.write(html)
    print(f"Report saved to {REPORT_FILE}")

def get_service_name(port):
    common = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
        110: 'POP3', 123: 'NTP', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
        161: 'SNMP', 162: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
        465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt'
    }
    return common.get(port, 'Unknown')

# Flask routes
@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/start', methods=['POST'])
def api_start():
    data = request.get_json() or {}
    interface = data.get('interface')
    filter_str = data.get('filter', 'ip')
    success = start_capture(interface, filter_str)
    return jsonify({'success': success, 'running': capture_running})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    stop_capture()
    return jsonify({'success': True, 'report': str(REPORT_FILE)})

@app.route('/api/status')
def api_status():
    with packet_lock:
        current_stats = {
            'total_packets': stats['total_packets'],
            'allowed': stats['allowed'],
            'blocked': stats['blocked'],
            'top_ports': dict(stats['top_ports'].most_common(10)),
            'top_ips': dict(stats['top_ips'].most_common(10)),
            'top_domains': dict(stats['top_domains'].most_common(10)),
            'protocols': dict(stats['protocols']),
            'running': capture_running,
            'start_time': stats['start_time']
        }
    return jsonify(current_stats)

@app.route('/api/report')
def api_report():
    if REPORT_FILE.exists():
        return REPORT_FILE.read_text()
    return jsonify({'error': 'No report generated yet'}), 404

# Graceful shutdown
def signal_handler(sig, frame):
    print("\nShutting down...")
    stop_capture()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    print(f"Scapy available: {SCAVAILABLE}")
    if not SCAVAILABLE:
        print("Install scapy for packet capture: pip install scapy")
        print("On Windows, also install Npcap: https://npcap.com/")
    app.run(host='0.0.0.0', port=5001, debug=True)