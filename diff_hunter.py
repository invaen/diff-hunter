#!/usr/bin/env python3
"""
Diff Hunter - Monitor targets for changes, catch new attack surface first.

Usage:
    diff-hunter add target.com          # Add target to monitor
    diff-hunter scan                    # Run scan on all targets
    diff-hunter scan target.com         # Scan specific target
    diff-hunter watch                   # Continuous monitoring
    diff-hunter report                  # Show recent changes
"""

import json
import sys
import os
import hashlib
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import socket
import ssl
import http.client
import re

__version__ = "1.0.0"

# Colors
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; E = '\033[0m'

    @classmethod
    def disable(cls):
        cls.R = cls.G = cls.Y = cls.B = cls.M = cls.C = cls.W = cls.E = ''

def banner():
    print(f"""{C.C}
    ╔╦╗╦╔═╗╔═╗  ╦ ╦╦ ╦╔╗╔╔╦╗╔═╗╦═╗
     ║║║╠╣ ╠╣   ╠═╣║ ║║║║ ║ ║╣ ╠╦╝
    ═╩╝╩╚  ╚    ╩ ╩╚═╝╝╚╝ ╩ ╚═╝╩╚═
    {C.W}Catch new attack surface first{C.E}
    """)

class DiffHunter:
    def __init__(self, webhook_url=None):
        self.data_dir = Path.home() / '.bounty' / 'diff-hunter'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.targets_file = self.data_dir / 'targets.json'
        self.history_dir = self.data_dir / 'history'
        self.history_dir.mkdir(exist_ok=True)
        self.alerts_file = self.data_dir / 'alerts.json'
        self.config_file = self.data_dir / 'config.json'
        self.webhook_url = webhook_url or self.load_config().get('webhook_url')

        self.targets = self.load_targets()
        self.alerts = self.load_alerts()

    def load_config(self):
        if self.config_file.exists():
            try:
                return json.loads(self.config_file.read_text())
            except json.JSONDecodeError:
                return {}
        return {}

    def save_config(self, config):
        self.config_file.write_text(json.dumps(config, indent=2))

    def log(self, msg, level='info'):
        icons = {'info': f'{C.B}[*]{C.E}', 'success': f'{C.G}[+]{C.E}',
                 'warn': f'{C.Y}[!]{C.E}', 'error': f'{C.R}[-]{C.E}',
                 'alert': f'{C.R}[🚨]{C.E}', 'new': f'{C.G}[NEW]{C.E}'}
        print(f"{icons.get(level, icons['info'])} {msg}")

    def load_targets(self):
        if self.targets_file.exists():
            try:
                return json.loads(self.targets_file.read_text())
            except json.JSONDecodeError:
                self.log("Failed to parse targets.json, starting with empty targets", 'warn')
                return {}
        return {}

    def save_targets(self):
        self.targets_file.write_text(json.dumps(self.targets, indent=2))

    def load_alerts(self):
        if self.alerts_file.exists():
            try:
                return json.loads(self.alerts_file.read_text())
            except json.JSONDecodeError:
                self.log("Failed to parse alerts.json, starting with empty alerts", 'warn')
                return []
        return []

    def save_alerts(self):
        self.alerts_file.write_text(json.dumps(self.alerts, indent=2))

    def send_webhook(self, changes):
        """Send alert to webhook (Discord, Slack, or generic HTTP)"""
        if not self.webhook_url or not changes:
            return

        # Build message
        lines = [f"**Diff Hunter** — {len(changes)} change(s) detected\n"]
        for c in changes[:15]:  # Cap at 15 to avoid huge payloads
            if c['type'] == 'new_subdomain':
                lines.append(f"🆕 New subdomain: `{c['subdomain']}`")
            elif c['type'] == 'new_endpoint':
                lines.append(f"🔓 New endpoint: `{c['host']}{c['path']}`")
            elif c['type'] == 'status_change':
                lines.append(f"⚡ Status change: `{c['host']}` {c['old']} → {c['new']}")
            elif c['type'] == 'content_change':
                lines.append(f"📝 Content changed: `{c['host']}`")
            elif c['type'] == 'dns_change':
                lines.append(f"🔀 DNS change: `{c['host']}` [{c.get('record', 'A')}]")
        if len(changes) > 15:
            lines.append(f"... and {len(changes) - 15} more")

        text = "\n".join(lines)

        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.webhook_url)
            is_discord = 'discord.com' in parsed.netloc
            is_slack = 'hooks.slack.com' in parsed.netloc

            if is_discord:
                payload = json.dumps({"content": text}).encode()
            elif is_slack:
                payload = json.dumps({"text": text.replace('**', '*')}).encode()
            else:
                payload = json.dumps({"text": text, "changes": changes}).encode()

            import urllib.request
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json', 'User-Agent': 'diff-hunter'},
                method='POST'
            )
            urllib.request.urlopen(req, timeout=10)
            self.log("Webhook notification sent", 'success')
        except Exception as e:
            self.log(f"Webhook failed: {e}", 'warn')

    # ==================== TARGET MANAGEMENT ====================

    def add_target(self, domain):
        """Add a new target to monitor"""
        domain = domain.lower().replace('https://', '').replace('http://', '').strip('/')

        if '.' not in domain or ' ' in domain or not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$', domain):
            self.log(f"Invalid domain: {domain}", 'error')
            return

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

    def resolve_dns(self, hostname):
        """Resolve DNS records for a hostname"""
        records = {}
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
            records['A'] = sorted(set(addr[4][0] for addr in ips))
        except (socket.gaierror, OSError):
            records['A'] = []
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            records['AAAA'] = sorted(set(addr[4][0] for addr in ips))
        except (socket.gaierror, OSError):
            records['AAAA'] = []
        try:
            cname = socket.getfqdn(hostname)
            if cname != hostname:
                records['CNAME'] = cname
        except (socket.gaierror, OSError):
            pass
        return records

    def check_dns_changes(self, domain, target_data, changes):
        """Check for DNS record changes across subdomains"""
        sample_hosts = list(target_data.get('subdomains', []))[:20]

        dns_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.resolve_dns, h): h for h in sample_hosts}
            for future in as_completed(futures):
                host = futures[future]
                dns_results[host] = future.result()

        previous_dns = target_data.get('dns_records', {})

        for host, current in dns_results.items():
            prev = previous_dns.get(host, {})
            if prev:
                # Check for IP changes
                if current.get('A') != prev.get('A') and (current.get('A') or prev.get('A')):
                    self.log(f"DNS change on {host}: {prev.get('A', [])} → {current.get('A', [])}", 'alert')
                    changes.append({
                        'type': 'dns_change',
                        'host': host,
                        'record': 'A',
                        'old': prev.get('A', []),
                        'new': current.get('A', []),
                        'timestamp': datetime.now().isoformat()
                    })
                # Check for CNAME changes (potential subdomain takeover)
                if current.get('CNAME') != prev.get('CNAME'):
                    self.log(f"CNAME change on {host}: {prev.get('CNAME', 'none')} → {current.get('CNAME', 'none')}", 'alert')
                    changes.append({
                        'type': 'dns_change',
                        'host': host,
                        'record': 'CNAME',
                        'old': prev.get('CNAME', ''),
                        'new': current.get('CNAME', ''),
                        'timestamp': datetime.now().isoformat()
                    })

        target_data['dns_records'] = dns_results

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
            try:
                conn.request('GET', p.path or '/', headers={'User-Agent': 'Mozilla/5.0'})
                resp = conn.getresponse()
                body = resp.read()

                return {
                    'status': resp.status,
                    'headers_hash': hashlib.md5(str(dict(resp.getheaders())).encode()).hexdigest()[:8],
                    'body_hash': hashlib.md5(body).hexdigest()[:8],
                    'body_length': len(body),
                    'server': resp.getheader('Server', 'Unknown')
                }
            finally:
                conn.close()
        except Exception as e:
            return None

    def check_interesting_paths(self, host):
        """Check for new interesting paths"""
        paths = [
            # Version control
            '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/dirstate',
            # Environment and config
            '/.env', '/.env.bak', '/.env.local', '/.env.production',
            '/.env.staging', '/config.json', '/config.yml', '/config.xml',
            # Web server
            '/.htaccess', '/.htpasswd', '/web.config', '/server-status',
            '/server-info', '/nginx.conf',
            # API documentation
            '/swagger.json', '/swagger-ui.html', '/swagger/v1/swagger.json',
            '/api/swagger.json', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api/v1/docs', '/api/v2/docs', '/redoc',
            '/graphql', '/graphiql', '/altair', '/playground',
            # Actuator / Spring Boot
            '/actuator', '/actuator/health', '/actuator/env',
            '/actuator/configprops', '/actuator/mappings',
            '/actuator/beans', '/actuator/heapdump', '/actuator/threaddump',
            # Admin panels
            '/admin', '/admin/login', '/administrator', '/wp-admin',
            '/wp-login.php', '/phpmyadmin', '/adminer.php',
            '/cpanel', '/webmail', '/_admin',
            # Common files
            '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.well-known/security.txt', '/.well-known/openid-configuration',
            # Debug and diagnostics
            '/debug', '/trace', '/phpinfo.php', '/info.php',
            '/elmah.axd', '/trace.axd', '/test', '/test.php',
            '/.DS_Store', '/Thumbs.db',
            # Backup files
            '/backup.sql', '/backup.zip', '/db.sql', '/dump.sql',
            '/database.sql', '/site.tar.gz', '/backup.tar.gz',
            # Cloud metadata
            '/latest/meta-data/', '/.aws/credentials',
            # Package files (dependency disclosure)
            '/package.json', '/composer.json', '/Gemfile',
            '/requirements.txt', '/Pipfile',
            # User enumeration
            '/wp-json/wp/v2/users', '/api/users', '/api/v1/users',
            # JavaScript source maps
            '/main.js.map', '/app.js.map', '/bundle.js.map',
            # Error pages (info disclosure)
            '/error', '/404', '/500',
            # Webpack / build artifacts
            '/webpack.config.js', '/manifest.json', '/asset-manifest.json',
            # Jenkins / CI
            '/jenkins', '/jenkins/login', '/.circleci/config.yml',
            '/.github/workflows',
        ]

        def check_path(path):
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, timeout=3, context=context)
                try:
                    conn.request('GET', path, headers={'User-Agent': 'Mozilla/5.0'})
                    resp = conn.getresponse()
                    if resp.status == 200:
                        return path
                finally:
                    conn.close()
            except (socket.timeout, ConnectionError, ssl.SSLError, OSError):
                pass
            return None

        found = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(check_path, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

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

        # 2. Check response changes on known hosts (concurrent)
        sample_hosts = list(current_subs)[:20]  # Check up to 20 hosts

        hash_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.get_response_hash, h): h for h in sample_hosts}
            for future in as_completed(futures):
                host = futures[future]
                hash_results[host] = future.result()

        for host, current_hash in hash_results.items():
            if not current_hash:
                continue

            previous_hash = target_data.get('response_hashes', {}).get(host)

            if previous_hash and not initial:
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

        # 4. Check DNS record changes
        if not initial:
            self.check_dns_changes(domain, target_data, changes)
        else:
            # Capture initial DNS baseline
            self.check_dns_changes(domain, target_data, [])

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

            # Send webhook notification
            self.send_webhook(changes)

        self.log(f"Scan complete. {len(changes)} changes detected.", 'success' if not changes else 'alert')
        return changes

    def scan_all(self):
        """Scan all monitored targets"""
        banner()
        if not self.targets:
            self.log("No targets to scan", 'warn')
            return []

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

        return total_changes

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
                elif alert_type == 'dns_change':
                    print(f"  • {alert['host']} [{alert.get('record', 'A')}]: {alert.get('old', '?')} → {alert.get('new', '?')}")
                else:
                    print(f"  • {alert.get('host', alert.get('domain', 'unknown'))}")
            print()


def main():
    parser = argparse.ArgumentParser(description='Diff Hunter - Monitor targets for changes')
    parser.add_argument('-V', '--version', action='version', version=f'diff-hunter {__version__}')
    parser.add_argument('--webhook', help='Webhook URL for notifications (Discord, Slack, or generic)')
    parser.add_argument('--no-color', action='store_true', help='Disable ANSI color output')
    parser.add_argument('--json', action='store_true', dest='json_output', help='Output results as JSON')
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

    # Configure webhook
    config_parser = subparsers.add_parser('config', help='Configure settings')
    config_parser.add_argument('--set-webhook', help='Set persistent webhook URL')
    config_parser.add_argument('--clear-webhook', action='store_true', help='Remove webhook URL')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')

    args = parser.parse_args()

    if args.no_color or args.json_output:
        C.disable()

    hunter = DiffHunter(webhook_url=getattr(args, 'webhook', None))

    if args.command == 'config':
        config = hunter.load_config()
        if args.set_webhook:
            config['webhook_url'] = args.set_webhook
            hunter.save_config(config)
            hunter.log(f"Webhook set: {args.set_webhook[:50]}...", 'success')
        elif args.clear_webhook:
            config.pop('webhook_url', None)
            hunter.save_config(config)
            hunter.log("Webhook removed", 'success')
        elif args.show:
            if config:
                for k, v in config.items():
                    print(f"  {k}: {v}")
            else:
                hunter.log("No configuration set", 'info')
        else:
            config_parser.print_help()
    elif args.command == 'add':
        hunter.add_target(args.domain)
    elif args.command == 'remove':
        hunter.remove_target(args.domain)
    elif args.command == 'list':
        hunter.list_targets()
    elif args.command == 'scan':
        if args.domain:
            changes = hunter.scan_target(args.domain)
        else:
            changes = hunter.scan_all()
        if args.json_output:
            print(json.dumps(changes or [], indent=2))
    elif args.command == 'watch':
        hunter.watch(args.interval)
    elif args.command == 'report':
        hunter.show_report(args.days)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
