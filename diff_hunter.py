#!/usr/bin/env python3
"""
Diff Hunter - Monitor targets for changes, catch new attack surface first.

Usage:
    python hunter.py add target.com          # Add target to monitor
    python hunter.py scan                    # Run scan on all targets
    python hunter.py scan target.com         # Scan specific target
    python hunter.py watch                   # Continuous monitoring
    python hunter.py report                  # Show recent changes
"""

import subprocess
import json
import sys
import os
import hashlib
import argparse
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
import http.client
import difflib

__version__ = "1.0.0"

# Colors
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; E = '\033[0m'

def banner():
    print(f"""{C.C}
    ╔╦╗╦╔═╗╔═╗  ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
     ║║║╠╣ ╠╣   ╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ═╩╝╩╚  ╚    ╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═
    {C.W}Catch new attack surface first{C.E}
    """)

class DiffHunter:
    def __init__(self):
        self.data_dir = Path.home() / '.bounty' / 'diff-hunter'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.targets_file = self.data_dir / 'targets.json'
        self.history_dir = self.data_dir / 'history'
        self.history_dir.mkdir(exist_ok=True)
        self.alerts_file = self.data_dir / 'alerts.json'

        self.targets = self.load_targets()
        self.alerts = self.load_alerts()

    def log(self, msg, level='info'):
        icons = {'info': f'{C.B}[*]{C.E}', 'success': f'{C.G}[+]{C.E}',
                 'warn': f'{C.Y}[!]{C.E}', 'error': f'{C.R}[-]{C.E}',
                 'alert': f'{C.R}[🚨]{C.E}', 'new': f'{C.G}[NEW]{C.E}'}
        print(f"{icons.get(level, icons['info'])} {msg}")

    def load_targets(self):
        if self.targets_file.exists():
            return json.loads(self.targets_file.read_text())
        return {}

    def save_targets(self):
        self.targets_file.write_text(json.dumps(self.targets, indent=2))

    def load_alerts(self):
        if self.alerts_file.exists():
            return json.loads(self.alerts_file.read_text())
        return []

    def save_alerts(self):
        self.alerts_file.write_text(json.dumps(self.alerts, indent=2))

    # ==================== TARGET MANAGEMENT ====================

    def add_target(self, domain):
        """Add a new target to monitor"""
        domain = domain.lower().replace('https://', '').replace('http://', '').strip('/')

        if domain in self.targets:
            self.log(f"{domain} already being monitored", 'warn')
            return

        self.targets[domain] = {
            'added': datetime.now().isoformat(),
            'last_scan': None,
            'subdomains': [],
            'endpoints': {},
            'technologies': {},
            'response_hashes': {}
        }
        self.save_targets()
        self.log(f"Added {domain} to monitoring", 'success')

        # Initial scan
        self.log("Running initial scan...")
        self.scan_target(domain, initial=True)

    def remove_target(self, domain):
        """Remove target from monitoring"""
        if domain in self.targets:
            del self.targets[domain]
            self.save_targets()
            self.log(f"Removed {domain}", 'success')
        else:
            self.log(f"{domain} not found", 'error')

    def list_targets(self):
        """List all monitored targets"""
        if not self.targets:
            self.log("No targets being monitored. Add one with: diff-hunter add domain.com", 'warn')
            return

        print(f"\n{C.Y}Monitored Targets:{C.E}")
        for domain, data in self.targets.items():
            last_scan = data.get('last_scan', 'Never')
            subcount = len(data.get('subdomains', []))
            print(f"  {C.G}•{C.E} {domain}")
            print(f"    Subdomains: {subcount} | Last scan: {last_scan}")
        print()

    # ==================== SCANNING ====================

    def get_subdomains(self, domain):
        """Get current subdomains via crt.sh"""
        subdomains = set()
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub and sub.endswith(domain):
                            subdomains.add(sub)
        except Exception as e:
            self.log(f"crt.sh error: {e}", 'warn')

        return subdomains

    def get_response_hash(self, url):
        """Get hash of response for change detection"""
        try:
            parsed = url if url.startswith('http') else f'https://{url}'
            from urllib.parse import urlparse
            p = urlparse(parsed)
            host = p.netloc or p.path

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            conn = http.client.HTTPSConnection(host, timeout=5, context=context)
            conn.request('GET', p.path or '/', headers={'User-Agent': 'Mozilla/5.0'})
            resp = conn.getresponse()
            body = resp.read()
            conn.close()

            return {
                'status': resp.status,
                'headers_hash': hashlib.md5(str(dict(resp.getheaders())).encode()).hexdigest()[:8],
                'body_hash': hashlib.md5(body).hexdigest()[:8],
                'body_length': len(body),
                'server': resp.getheader('Server', 'Unknown')
            }
        except Exception as e:
            return None

    def check_interesting_paths(self, host):
        """Check for new interesting paths"""
        paths = [
            '/.git/HEAD', '/.env', '/robots.txt', '/sitemap.xml',
            '/swagger.json', '/api/swagger.json', '/graphql',
            '/actuator/health', '/debug', '/.well-known/security.txt',
            '/openapi.json', '/api-docs', '/api/v1/docs',
            '/.DS_Store', '/wp-json/wp/v2/users', '/server-status',
            '/server-info', '/elmah.axd', '/trace.axd',
            '/actuator/env', '/actuator/configprops',
            '/admin', '/admin/login', '/phpinfo.php',
            '/.htaccess', '/crossdomain.xml', '/clientaccesspolicy.xml',
        ]

        found = []
        for path in paths:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, timeout=3, context=context)
                conn.request('GET', path, headers={'User-Agent': 'Mozilla/5.0'})
                resp = conn.getresponse()
                if resp.status == 200:
                    found.append(path)
                conn.close()
            except Exception:
                pass

        return found

    def scan_target(self, domain, initial=False):
        """Scan a target for changes"""
        if domain not in self.targets:
            self.log(f"{domain} not in targets", 'error')
            return

        self.log(f"Scanning {domain}...")
        target_data = self.targets[domain]
        changes = []

        # 1. Check for new subdomains
        current_subs = self.get_subdomains(domain)
        previous_subs = set(target_data.get('subdomains', []))

        new_subs = current_subs - previous_subs
        removed_subs = previous_subs - current_subs

        if new_subs and not initial:
            self.log(f"NEW SUBDOMAINS FOUND!", 'alert')
            for sub in new_subs:
                self.log(f"  {C.G}+ {sub}{C.E}", 'new')
                changes.append({
                    'type': 'new_subdomain',
                    'domain': domain,
                    'subdomain': sub,
                    'timestamp': datetime.now().isoformat()
                })

        # Update stored subdomains
        target_data['subdomains'] = list(current_subs)

        # 2. Check response changes on known hosts
        sample_hosts = list(current_subs)[:20]  # Check up to 20 hosts

        for host in sample_hosts:
            current_hash = self.get_response_hash(host)
            if not current_hash:
                continue

            previous_hash = target_data.get('response_hashes', {}).get(host)

            if previous_hash and not initial:
                # Check for changes
                if current_hash['status'] != previous_hash.get('status'):
                    self.log(f"Status change on {host}: {previous_hash.get('status')} → {current_hash['status']}", 'alert')
                    changes.append({
                        'type': 'status_change',
                        'host': host,
                        'old': previous_hash.get('status'),
                        'new': current_hash['status'],
                        'timestamp': datetime.now().isoformat()
                    })

                if current_hash['body_hash'] != previous_hash.get('body_hash'):
                    self.log(f"Content change on {host}", 'warn')
                    changes.append({
                        'type': 'content_change',
                        'host': host,
                        'timestamp': datetime.now().isoformat()
                    })

            # Update hash
            if 'response_hashes' not in target_data:
                target_data['response_hashes'] = {}
            target_data['response_hashes'][host] = current_hash

        # 3. Check for new interesting endpoints
        main_host = domain
        current_endpoints = self.check_interesting_paths(main_host)
        previous_endpoints = target_data.get('endpoints', {}).get(main_host, [])

        new_endpoints = set(current_endpoints) - set(previous_endpoints)
        if new_endpoints and not initial:
            self.log(f"NEW ENDPOINTS FOUND!", 'alert')
            for ep in new_endpoints:
                self.log(f"  {C.G}+ {ep}{C.E}", 'new')
                changes.append({
                    'type': 'new_endpoint',
                    'host': main_host,
                    'path': ep,
                    'timestamp': datetime.now().isoformat()
                })

        if 'endpoints' not in target_data:
            target_data['endpoints'] = {}
        target_data['endpoints'][main_host] = current_endpoints

        # Save changes
        target_data['last_scan'] = datetime.now().isoformat()
        self.targets[domain] = target_data
        self.save_targets()

        # Store alerts
        if changes:
            self.alerts.extend(changes)
            self.save_alerts()

            # Save to history
            history_file = self.history_dir / f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            history_file.write_text(json.dumps(changes, indent=2))

        self.log(f"Scan complete. {len(changes)} changes detected.", 'success' if not changes else 'alert')
        return changes

    def scan_all(self):
        """Scan all monitored targets"""
        banner()
        if not self.targets:
            self.log("No targets to scan", 'warn')
            return

        total_changes = []
        for domain in self.targets:
            changes = self.scan_target(domain)
            if changes:
                total_changes.extend(changes)
            print()

        print(f"\n{C.Y}═══ Scan Summary ═══{C.E}")
        print(f"Targets scanned: {len(self.targets)}")
        print(f"Changes detected: {len(total_changes)}")

        if total_changes:
            print(f"\n{C.R}⚠ ACTION REQUIRED - New attack surface detected!{C.E}")

    def watch(self, interval=3600):
        """Continuous monitoring mode"""
        banner()
        self.log(f"Starting continuous monitoring (interval: {interval}s)")
        self.log("Press Ctrl+C to stop\n")

        while True:
            try:
                self.scan_all()
                self.log(f"Next scan in {interval} seconds...")
                time.sleep(interval)
            except KeyboardInterrupt:
                self.log("\nStopping monitor", 'warn')
                break

    def show_report(self, days=7):
        """Show recent changes"""
        banner()
        print(f"{C.Y}Recent Changes (last {days} days):{C.E}\n")

        if not self.alerts:
            self.log("No changes detected yet", 'info')
            return

        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=days)

        recent = []
        for alert in self.alerts:
            try:
                alert_time = datetime.fromisoformat(alert['timestamp'])
                if alert_time > cutoff:
                    recent.append(alert)
            except Exception:
                pass

        if not recent:
            self.log(f"No changes in the last {days} days", 'info')
            return

        # Group by type
        by_type = {}
        for alert in recent:
            t = alert['type']
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(alert)

        for alert_type, alerts in by_type.items():
            print(f"{C.G}{alert_type.upper()}{C.E} ({len(alerts)})")
            for alert in alerts[:10]:  # Show up to 10 per type
                if alert_type == 'new_subdomain':
                    print(f"  • {alert['subdomain']}")
                elif alert_type == 'new_endpoint':
                    print(f"  • {alert['host']}{alert['path']}")
                elif alert_type == 'status_change':
                    print(f"  • {alert['host']}: {alert['old']} → {alert['new']}")
                else:
                    print(f"  • {alert.get('host', alert.get('domain', 'unknown'))}")
            print()


def main():
    parser = argparse.ArgumentParser(description='Diff Hunter - Monitor targets for changes')
    parser.add_argument('-V', '--version', action='version', version=f'diff-hunter {__version__}')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Add target
    add_parser = subparsers.add_parser('add', help='Add target to monitor')
    add_parser.add_argument('domain', help='Domain to monitor')

    # Remove target
    rm_parser = subparsers.add_parser('remove', help='Remove target from monitoring')
    rm_parser.add_argument('domain', help='Domain to remove')

    # List targets
    subparsers.add_parser('list', help='List monitored targets')

    # Scan
    scan_parser = subparsers.add_parser('scan', help='Scan for changes')
    scan_parser.add_argument('domain', nargs='?', help='Specific domain to scan')

    # Watch
    watch_parser = subparsers.add_parser('watch', help='Continuous monitoring')
    watch_parser.add_argument('-i', '--interval', type=int, default=3600, help='Scan interval in seconds')

    # Report
    report_parser = subparsers.add_parser('report', help='Show recent changes')
    report_parser.add_argument('-d', '--days', type=int, default=7, help='Days to show')

    args = parser.parse_args()
    hunter = DiffHunter()

    if args.command == 'add':
        hunter.add_target(args.domain)
    elif args.command == 'remove':
        hunter.remove_target(args.domain)
    elif args.command == 'list':
        hunter.list_targets()
    elif args.command == 'scan':
        if args.domain:
            hunter.scan_target(args.domain)
        else:
            hunter.scan_all()
    elif args.command == 'watch':
        hunter.watch(args.interval)
    elif args.command == 'report':
        hunter.show_report(args.days)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
