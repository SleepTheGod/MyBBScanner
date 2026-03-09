#!/usr/bin/env python3
"""
MyBB Remote Security Assessment Tool - Enhanced Edition
For authorized penetration testing only
"""

# ASCII Art Banner
print("""
            ███╗   ███╗██╗   ██╗██████╗ ██████╗             
            ████╗ ████║╚██╗ ██╔╝██╔══██╗██╔══██╗           
            ██╔████╔██║ ╚████╔╝ ██████╔╝██████╔╝           
            ██║╚██╔╝██║  ╚██╔╝  ██╔══██╗██╔══██╗           
            ██║ ╚═╝ ██║   ██║   ██████╔╝██████╔╝           
            ╚═╝     ╚═╝   ╚═╝   ╚═════╝ ╚═════╝           
                                                          
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
| Version 1.0 By Taylor Christian Newsome | TsGh.org | Pl0x.org |
""")

import requests
import sys
import re
import json
import time
import argparse
import hashlib
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import warnings
# Initialize colorama
init(autostrip=True)
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class MyBBSecurityTester:
    def __init__(self, target_url, threads=10, timeout=15, verify_ssl=False, proxy=None, depth=2):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.depth = depth
        self.session = self._create_session()
        self.vulnerabilities = []
        self.info_findings = []
        self.discovered_urls = set()
        
        # Configure proxy if provided
        self.proxies = {'http': proxy, 'https': proxy} if proxy else None
        
        # Database exposure patterns
        self.db_exposure_patterns = [
            (r'INSERT INTO `?mybb_users`?.*VALUES', 'MyBB User Table Dump - Critical Data Exposure'),
            (r'(`uid`, `username`, `password`, `salt`, `email`)', 'User Credential Structure Exposure'),
            (r'password` varchar\(500\)', 'Password Hash Field Exposure'),
            (r'salt` varchar\(10\)', 'Password Salt Field Exposure'),
            (r'mybb_users.*ENGINE=InnoDB', 'Database Schema Exposure'),
            (r'mybb_users.*AUTO_INCREMENT=\d+', 'User ID Range Exposure'),
            (r'username` varchar\(120\)', 'Username Field Structure'),
            (r'email` varchar\(220\)', 'Email Field Structure'),
            (r'regip` varbinary\(16\)', 'Registration IP Field'),
            (r'lastip` varbinary\(16\)', 'Last IP Field'),
            (r'loginkey` varchar\(50\)', 'Login Key Field Exposure'),
        ]
        
        # Common backup file patterns
        self.backup_patterns = [
            '*.sql', '*.bak', '*.backup', '*.old', '*.txt',
            'backup_*.sql', 'db_*.sql', 'database_*.sql',
            'mybb_*.sql', 'forum_*.sql', '*.dump', '*.dmp',
            '*.gz', '*.zip', '*.tar', '*.7z', '*.rar'
        ]
        
        # SQL error patterns for database detection
        self.sql_error_patterns = [
            'Table .*mybb_users.* doesn\'t exist',
            'Unknown column.*mybb_users',
            'mybb_users.*MySQL',
            'InnoDB.*mybb_users',
            'SELECT.*FROM mybb_users',
            'mybb_users.*PRIMARY KEY',
            'mybb_users.*FOREIGN KEY',
        ]
    
    def _create_session(self):
        """Create a configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        return session
    
    def _make_request(self, url, method='GET', params=None, data=None, headers=None):
        """Make HTTP request with error handling"""
        try:
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=req_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                proxies=self.proxies,
                allow_redirects=True
            )
            return response
        except requests.exceptions.Timeout:
            self._log(f"Timeout: {url}", 'warning')
        except requests.exceptions.ConnectionError:
            self._log(f"Connection error: {url}", 'warning')
        except Exception as e:
            self._log(f"Request error: {e}", 'error')
        return None
    
    def _log(self, message, level='info'):
        """Color-coded logging"""
        colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT,
            'database': Fore.MAGENTA + Style.BRIGHT
        }
        prefix = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[-]',
            'critical': '[!!!]',
            'database': '[DB]'
        }
        print(f"{colors.get(level, Fore.WHITE)}{prefix.get(level, '[*]')} {message}{Style.RESET_ALL}")
    
    def _add_finding(self, finding_type, severity, description, url, evidence=None, remediation=None):
        """Add finding to results"""
        finding = {
            'type': finding_type,
            'severity': severity,
            'description': description,
            'url': url,
            'evidence': evidence[:500] if evidence else None,
            'timestamp': datetime.now().isoformat(),
            'remediation': remediation
        }
        
        if severity in ['critical', 'high']:
            self.vulnerabilities.append(finding)
            self._log(f"{description} - {url}", 'critical' if severity == 'critical' else 'error')
        else:
            self.info_findings.append(finding)
            self._log(f"{description} - {url}", 'warning')
    
    def check_database_exposure(self):
        """Check for exposed database dumps and schema information"""
        self._log("Checking for database exposure...", 'database')
        
        # Common locations for database dumps
        db_paths = [
            # SQL dumps
            'dump.sql', 'backup.sql', 'database.sql', 'db.sql', 'forum.sql',
            'mybb.sql', 'mybb_backup.sql', 'backup/mybb.sql', 'sql/mybb.sql',
            'backups/forum.sql', 'backups/mybb.sql', 'admin/backup.sql',
            'install/backup.sql', 'install/data.sql', 'install/sql.sql',
            
            # Backup files
            'backup.zip', 'backup.tar.gz', 'forum_backup.zip', 'site_backup.zip',
            'www_backup.zip', 'htdocs_backup.zip', 'public_html_backup.zip',
            
            # Config files
            'inc/config.php', 'inc/settings.php', 'config.php.bak', 'config.php.old',
            'inc/db_mysql.php', 'inc/db_mysqli.php', 'inc/db_pdo.php',
            
            # Environment files
            '.env', '.env.local', '.env.backup', 'env.txt',
            
            # Cache files
            'cache/sql_cache.php', 'cache/site_cache.php',
            
            # Git exposed files
            '.git/index', '.git/config', '.git/logs/HEAD',
        ]
        
        def check_path(path):
            url = urljoin(self.target_url, path)
            response = self._make_request(url)
            if not response or response.status_code != 200:
                return
            
            content = response.text
            
            # Check for database schema patterns
            for pattern, description in self.db_exposure_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # Extract sample of the exposed data
                    sample_lines = []
                    for line in content.split('\n')[:10]:
                        if 'INSERT INTO' in line or 'CREATE TABLE' in line:
                            sample_lines.append(line[:200])
                    
                    evidence = '\n'.join(sample_lines)
                    
                    # Check for actual user data
                    if 'INSERT INTO `mybb_users`' in content:
                        # Count number of user inserts
                        user_inserts = len(re.findall(r'INSERT INTO `?mybb_users`?', content))
                        if user_inserts > 0:
                            self._add_finding(
                                'Critical Database Exposure',
                                'critical',
                                f"COMPLETE USER DATABASE DUMP FOUND with approximately {user_inserts} user records",
                                url,
                                evidence,
                                "Immediately remove the SQL dump file, restrict access to backup directories, use .htaccess protection"
                            )
                            return
                    
                    self._add_finding(
                        'Database Schema Exposure',
                        'high',
                        f"Database structure exposed: {description}",
                        url,
                        evidence,
                        "Remove exposed database files, implement proper access controls"
                    )
                    return
            
            # Check for SQL content markers
            sql_markers = [
                '-- MySQL dump', '-- phpMyAdmin SQL Dump', 'CREATE TABLE',
                'DROP TABLE IF EXISTS', 'INSERT INTO', 'ENGINE=InnoDB',
                'CHARSET=utf8mb4', 'COLLATE=utf8mb4_general_ci'
            ]
            
            sql_matches = sum(1 for marker in sql_markers if marker.lower() in content.lower())
            if sql_matches >= 3:
                self._add_finding(
                    'Potential SQL Dump Exposure',
                    'high',
                    f"SQL database dump detected ({sql_matches} SQL markers found)",
                    url,
                    content[:500],
                    "Remove SQL dump files and secure backup directories"
                )
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_path, db_paths)
    
    def check_user_enumeration_advanced(self):
        """Advanced user enumeration checks"""
        self._log("Performing advanced user enumeration tests...", 'info')
        
        # Test for user existence via various endpoints
        user_tests = [
            ('member.php', {'action': 'profile', 'uid': 1}),
            ('member.php', {'action': 'profile', 'uid': 2}),
            ('member.php', {'action': 'profile', 'uid': 999999}),  # Non-existent
            ('member.php', {'action': 'profile', 'username': 'admin'}),
            ('member.php', {'action': 'profile', 'username': 'administrator'}),
            ('member.php', {'action': 'search', 'username': 'admin'}),
            ('member.php', {'action': 'search', 'username': 'administrator'}),
            ('memberlist.php', {'page': 1}),
            ('memberlist.php', {'username': 'admin', 'search': 1}),
            ('stats.php', {}),
            ('showteam.php', {}),
            ('member.php', {'action': 'buddy', 'uid': 1}),
        ]
        
        base_parsed = urlparse(self.target_url)
        base_url = f"{base_parsed.scheme}://{base_parsed.netloc}"
        
        for endpoint, params in user_tests:
            url = urljoin(base_url, endpoint)
            response = self._make_request(url, params=params)
            
            if not response:
                continue
            
            # Check for user enumeration indicators
            page_text = response.text.lower()
            
            # For non-existent user test
            if params.get('uid') == 999999:
                error_patterns = [
                    'invalid user',
                    'user not found',
                    'no user specified',
                    'does not exist'
                ]
                if not any(pattern in page_text for pattern in error_patterns):
                    self._add_finding(
                        'User Enumeration',
                        'medium',
                        f"Possible user enumeration via {endpoint}",
                        url,
                        f"Parameters: {params}"
                    )
            else:
                # Check for successful user data exposure
                if 'password' in page_text or 'email' in page_text:
                    if 'user profile' in page_text and 'joined' in page_text:
                        self._add_finding(
                            'User Data Exposure',
                            'high',
                            f"Potential user data exposed via {endpoint}",
                            url,
                            f"Parameters: {params}"
                        )
    
    def check_password_hash_exposure(self):
        """Check for exposed password hashes"""
        self._log("Checking for password hash exposure...", 'critical')
        
        # Patterns for various hash formats
        hash_patterns = [
            (r'[a-f0-9]{32}', 'MD5 Hash'),
            (r'[a-f0-9]{40}', 'SHA1 Hash'),
            (r'[a-f0-9]{64}', 'SHA256 Hash'),
            (r'[a-f0-9]{128}', 'SHA512 Hash'),
            (r'\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9\./]{53}', 'bcrypt Hash'),
            (r'\$6\$(rounds=\d+\$)?[A-Za-z0-9\./]{16}\$[A-Za-z0-9\./]{86}', 'SHA512crypt'),
        ]
        
        # Check common locations for hash exposure
        hash_locations = [
            'inc/config.php',
            'inc/settings.php',
            'admin/config.php',
            'cache/settings.php',
            'cache/config.php',
            '.env',
            'debug.log',
            'error.log',
            'php_errors.log',
        ]
        
        def check_hash_exposure(path):
            url = urljoin(self.target_url, path)
            response = self._make_request(url)
            if not response or response.status_code != 200:
                return
            
            content = response.text
            
            # Look for hash patterns
            for pattern, hash_type in hash_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    # Filter out false positives (like hex color codes)
                    valid_hashes = []
                    for match in matches[:5]:  # Limit to first 5
                        # Check if it looks like a real hash (not just a short hex string)
                        if len(match) >= 32 and not re.match(r'^[0-9a-f]{6}$', match):
                            valid_hashes.append(match)
                    
                    if valid_hashes:
                        self._add_finding(
                            'Password Hash Exposure',
                            'critical',
                            f"Potential {hash_type} exposed in {path}",
                            url,
                            f"Found hash: {valid_hashes[0][:32]}...",
                            "Remove exposed files, change all affected passwords immediately"
                        )
                        return
            
            # Look specifically for salt values
            salt_patterns = [
                (r"salt['\"]?\s*=>?\s*['\"]([^'\"]{8,})['\"]", 'Salt value'),
                (r"\$salt\s*=\s*['\"]([^'\"]+)['\"]", 'PHP salt variable'),
            ]
            
            for pattern, description in salt_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    self._add_finding(
                        'Salt Value Exposure',
                        'critical',
                        f"Password salt values exposed: {description}",
                        url,
                        f"Found salt: {matches[0][:32]}...",
                        "Salts should never be exposed - change all passwords"
                    )
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_hash_exposure, hash_locations)
    
    def check_sql_errors_advanced(self):
        """Advanced SQL error detection"""
        self._log("Checking for SQL error disclosures...", 'info')
        
        # SQL injection test points
        test_points = [
            ('member.php', {'action': 'profile', 'uid': "1'"}),
            ('member.php', {'action': 'profile', 'uid': "1 AND 1=1"}),
            ('member.php', {'action': 'profile', 'uid': "1 AND 1=2"}),
            ('forumdisplay.php', {'fid': "1'"}),
            ('forumdisplay.php', {'fid': "1 AND 1=1"}),
            ('showthread.php', {'tid': "1'"}),
            ('showthread.php', {'tid': "1 AND 1=1"}),
            ('search.php', {'keywords': "' OR '1'='1"}),
            ('member.php', {'username': "admin'--"}),
        ]
        
        base_parsed = urlparse(self.target_url)
        base_url = f"{base_parsed.scheme}://{base_parsed.netloc}"
        
        for endpoint, params in test_points:
            url = urljoin(base_url, endpoint)
            response = self._make_request(url, params=params)
            
            if not response:
                continue
            
            # Check for SQL errors in response
            sql_errors = [
                (r"SQL syntax.*MySQL", "MySQL syntax error"),
                (r"Unknown column.*'[^']+'", "Unknown column error"),
                (r"Table.*doesn't exist", "Missing table error"),
                (r"Duplicate entry.*for key", "Duplicate entry error"),
                (r"mysql_fetch_array", "MySQL fetch function error"),
                (r"mysql_num_rows", "MySQL num rows error"),
                (r"PDOException", "PDO Exception"),
                (r"mysqli_sql_exception", "MySQLi exception"),
                (r"Warning:.*mysql_", "MySQL warning"),
                (r"Unclosed quotation mark", "Unclosed quote error"),
                (r"Incorrect integer value", "Incorrect value error"),
            ]
            
            for pattern, error_desc in sql_errors:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self._add_finding(
                        'SQL Error Disclosure',
                        'high',
                        f"SQL error disclosed: {error_desc}",
                        f"{url}?{params}",
                        response.text[:500],
                        "Disable detailed error messages in production"
                    )
                    break
    
    def check_backup_files(self):
        """Check for common backup file patterns"""
        self._log("Checking for backup files...", 'info')
        
        # Common backup extensions and patterns
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.copy', '.txt',
            '.sql', '.dump', '.dmp', '.tar', '.tar.gz', '.tgz',
            '.zip', '.7z', '.rar', '.gz', '.bz2',
        ]
        
        common_files = [
            'config.php', 'settings.php', 'db_mysql.php',
            '.htaccess', '.env', 'index.php', 'global.php',
        ]
        
        for file in common_files:
            for ext in backup_extensions:
                path = file + ext
                url = urljoin(self.target_url, path)
                response = self._make_request(url)
                
                if response and response.status_code == 200:
                    # Check if it's actually a backup (has source code)
                    content = response.text
                    if '<?php' in content or '<?=' in content or 'CREATE TABLE' in content:
                        self._add_finding(
                            'Backup File Exposure',
                            'critical' if '.sql' in ext or 'config' in file else 'high',
                            f"Backup file exposed: {path}",
                            url,
                            content[:500],
                            f"Remove backup files, configure server to deny access to *{ext} files"
                        )
    
    def check_installer_files(self):
        """Check for left-over installation files"""
        self._log("Checking for installation files...", 'critical')
        
        installer_paths = [
            'install/', 'install/index.php', 'install/upgrade.php',
            'install/lock', 'install/install.php', 'install/database.php',
            'install/upgrade.php', 'install/upgrade12.php', 'install/upgrade13.php',
            'install/upgrade14.php', 'install/upgrade15.php', 'install/upgrade16.php',
            'install/upgrade17.php', 'install/upgrade18.php', 'install/upgrade19.php',
            'install/upgrade20.php', 'install/upgrade21.php', 'install/upgrade22.php',
            'install/upgrade23.php', 'install/upgrade24.php', 'install/upgrade25.php',
            'install/upgrade26.php', 'install/upgrade27.php', 'install/upgrade28.php',
            'install/upgrade29.php', 'install/upgrade30.php', 'install/upgrade31.php',
            'install/upgrade32.php', 'install/upgrade33.php', 'install/upgrade34.php',
            'install/upgrade35.php', 'install/upgrade36.php', 'install/upgrade37.php',
            'install/upgrade38.php', 'install/upgrade39.php', 'install/upgrade40.php',
            'install/resources/', 'install/resources/mybb_theme.xml',
        ]
        
        def check_installer(path):
            url = urljoin(self.target_url, path)
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                content = response.text.lower()
                
                # Check for installer indicators
                installer_indicators = [
                    'welcome to the mybb installation',
                    'mybb installation wizard',
                    'install mybb',
                    'installation process',
                    'step 1 of 5',
                    'database configuration',
                    'admin user',
                    'board settings',
                ]
                
                if any(indicator in content for indicator in installer_indicators):
                    self._add_finding(
                        'Installer Files Present',
                        'critical',
                        f"Installation wizard accessible! MyBB installer left exposed",
                        url,
                        content[:500],
                        "IMMEDIATELY delete the install directory! This is extremely dangerous."
                    )
                elif path.endswith('.php') and 'install' in path:
                    # Even if not the main installer, other install files may expose info
                    self._add_finding(
                        'Installation Files Exposed',
                        'high',
                        f"Installation-related file exposed: {path}",
                        url,
                        content[:500],
                        "Remove installation files from web root"
                    )
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_installer, installer_paths)
    
    def check_debug_modes(self):
        """Check for debug mode exposure"""
        self._log("Checking for debug modes...", 'info')
        
        debug_triggers = [
            ('?debug=1', 'Debug parameter'),
            ('?debug=true', 'Debug parameter'),
            ('?debug_mode=1', 'Debug parameter'),
            ('?dev=1', 'Development mode'),
            ('?development=1', 'Development mode'),
            ('?MYBB_DEBUG=1', 'MyBB debug constant'),
            ('?debug_output=1', 'Debug output'),
            ('?show_errors=1', 'Show errors'),
            ('?display_errors=1', 'Display errors'),
        ]
        
        for param, description in debug_triggers:
            url = self.target_url + param
            response = self._make_request(url)
            
            if not response:
                continue
            
            # Check for debug output
            debug_patterns = [
                'debug information',
                'mybb_debug',
                'queries executed',
                'php debug',
                'stack trace',
                'error_reporting',
                'display_errors',
                'memory usage',
                'generated in',
            ]
            
            page_text = response.text.lower()
            matches = [p for p in debug_patterns if p in page_text]
            
            if len(matches) > 2:
                self._add_finding(
                    'Debug Mode Exposed',
                    'high',
                    f"Debug information accessible via {description}",
                    url,
                    f"Debug patterns found: {', '.join(matches)}",
                    "Disable debug mode in production"
                )
    
    def check_user_data_leakage(self):
        """Check for user data leakage in source"""
        self._log("Checking for user data leakage...", 'critical')
        
        # Check various endpoints for user data
        user_endpoints = [
            'member.php?action=profile&uid=1',
            'member.php?action=profile&uid=2',
            'memberlist.php?perpage=5&order=desc&sort=regdate',
            'showteam.php',
            'stats.php?action=team',
        ]
        
        for endpoint in user_endpoints:
            url = urljoin(self.target_url, endpoint)
            response = self._make_request(url)
            
            if not response or response.status_code != 200:
                continue
            
            content = response.text
            
            # Look for email patterns
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails = re.findall(email_pattern, content)
            
            if emails:
                # Filter out common false positives
                filtered_emails = []
                for email in emails:
                    if not any(x in email for x in ['example.com', 'domain.com', 'yourdomain.com']):
                        filtered_emails.append(email)
                
                if filtered_emails:
                    self._add_finding(
                        'Email Exposure',
                        'high',
                        f"User email addresses exposed in {endpoint}",
                        url,
                        f"Sample emails: {', '.join(filtered_emails[:3])}",
                        "Review visibility settings for user information"
                    )
            
            # Look for IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            
            if ips:
                valid_ips = [ip for ip in ips if not ip.startswith('127.') and not ip.startswith('192.168.')]
                if valid_ips:
                    self._add_finding(
                        'IP Address Exposure',
                        'medium',
                        f"User IP addresses exposed in {endpoint}",
                        url,
                        f"Sample IPs: {', '.join(valid_ips[:3])}",
                        "Consider hiding IP addresses from public view"
                    )
    
    def check_version_disclosure(self):
        """Check for MyBB version disclosure"""
        self._log("Checking for version disclosure...", 'info')
        
        response = self._make_request(self.target_url)
        if not response:
            return
        
        content = response.text
        
        # Check meta generator
        soup = BeautifulSoup(content, 'html.parser')
        generator = soup.find('meta', {'name': 'generator'})
        if generator and generator.get('content'):
            version = generator.get('content')
            if 'MyBB' in version:
                self._add_finding(
                    'Version Disclosure',
                    'info',
                    f"MyBB version disclosed: {version}",
                    self.target_url,
                    version,
                    "Consider removing generator meta tag for security through obscurity"
                )
        
        # Check for version in comments
        version_patterns = [
            r'MyBB ([0-9.]+)',
            r'Powered by MyBB ([0-9.]+)',
            r'mybb_version = "([0-9.]+)"'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content)
            if match:
                version = match.group(1)
                self._add_finding(
                    'Version Disclosure',
                    'info',
                    f"MyBB version disclosed: {version}",
                    self.target_url,
                    version,
                    "Remove version information from source code"
                )
                break
    
    def check_admin_interfaces(self):
        """Check for exposed admin interfaces"""
        self._log("Checking for admin interfaces...", 'info')
        
        admin_paths = [
            'admin/', 'admin.php', 'admin/index.php', 'admin/login.php',
            'modcp.php', 'moderator.php', 'cp.php', 'admin/cp.php',
            'admin/admin.php', 'admin/control.php', 'admin/panel.php'
        ]
        
        def check_path(path):
            url = urljoin(self.target_url, path)
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                content = response.text.lower()
                admin_indicators = ['login', 'username', 'password', 'admin', 'moderator', 'control panel']
                
                if any(indicator in content for indicator in admin_indicators):
                    self._add_finding(
                        'Admin Interface Exposure',
                        'high',
                        f"Admin/moderator interface accessible",
                        url,
                        None,
                        "Restrict access to admin interfaces by IP or add additional authentication"
                    )
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_path, admin_paths)
    
    def run_quick_scan(self):
        """Run a quick scan (skip some heavy checks)"""
        self._log("Running quick scan mode...", 'info')
        self.check_version_disclosure()
        self.check_admin_interfaces()
        self.check_database_exposure()
        self.check_installer_files()
        self.check_backup_files()
        self.check_debug_modes()
    
    def run_full_scan(self):
        """Run a full comprehensive scan"""
        self._log("Running full scan mode...", 'info')
        self.check_version_disclosure()
        self.check_admin_interfaces()
        self.check_database_exposure()
        self.check_user_enumeration_advanced()
        self.check_password_hash_exposure()
        self.check_sql_errors_advanced()
        self.check_backup_files()
        self.check_installer_files()
        self.check_debug_modes()
        self.check_user_data_leakage()
    
    def generate_report(self, output_format='text'):
        """Generate detailed assessment report"""
        if output_format == 'json':
            report = {
                'target': self.target_url,
                'scan_time': datetime.now().isoformat(),
                'vulnerabilities': self.vulnerabilities,
                'information_gathered': self.info_findings,
                'summary': {
                    'critical_vulnerabilities': len([v for v in self.vulnerabilities if v['severity'] == 'critical']),
                    'high_vulnerabilities': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                    'medium_vulnerabilities': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                    'info_findings': len(self.info_findings),
                    'total_findings': len(self.vulnerabilities) + len(self.info_findings)
                },
                'remediation_priority': {
                    'immediate_action': [v for v in self.vulnerabilities if v['severity'] == 'critical'],
                    'high_priority': [v for v in self.vulnerabilities if v['severity'] == 'high'],
                    'medium_priority': [v for v in self.vulnerabilities if v['severity'] == 'medium']
                }
            }
            return json.dumps(report, indent=2)
        else:
            report_lines = []
            report_lines.append("\n" + "="*70)
            report_lines.append("MYBB SECURITY ASSESSMENT REPORT - ENHANCED EDITION")
            report_lines.append("="*70)
            report_lines.append(f"Target: {self.target_url}")
            report_lines.append(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("="*70)
            
            # Summary statistics
            critical_count = len([v for v in self.vulnerabilities if v['severity'] == 'critical'])
            high_count = len([v for v in self.vulnerabilities if v['severity'] == 'high'])
            medium_count = len([v for v in self.vulnerabilities if v['severity'] == 'medium'])
            info_count = len(self.info_findings)
            
            report_lines.append("\nSCAN SUMMARY:")
            report_lines.append("-"*40)
            report_lines.append(f"Critical Findings: {critical_count}")
            report_lines.append(f"High Findings: {high_count}")
            report_lines.append(f"Medium Findings: {medium_count}")
            report_lines.append(f"Informational: {info_count}")
            report_lines.append(f"Total: {critical_count + high_count + medium_count + info_count}")
            
            if critical_count > 0:
                report_lines.append(f"\nCRITICAL VULNERABILITIES FOUND - IMMEDIATE ACTION REQUIRED")
            
            if self.vulnerabilities:
                report_lines.append("\nVULNERABILITIES FOUND:")
                report_lines.append("-"*40)
                
                # Group by severity
                for severity in ['critical', 'high', 'medium']:
                    severity_findings = [v for v in self.vulnerabilities if v['severity'] == severity]
                    if severity_findings:
                        report_lines.append(f"\n{severity.upper()} SEVERITY:")
                        for v in severity_findings:
                            report_lines.append(f"\n  Type: {v['type']}")
                            report_lines.append(f"  Description: {v['description']}")
                            report_lines.append(f"  URL: {v['url']}")
                            if v.get('evidence'):
                                report_lines.append(f"  Evidence: {v['evidence'][:200]}...")
                            if v.get('remediation'):
                                report_lines.append(f"  Remediation: {v['remediation']}")
                            report_lines.append("  " + "-"*30)
            else:
                report_lines.append("\nNo vulnerabilities found.")
            
            if self.info_findings:
                report_lines.append("\nINFORMATION GATHERED:")
                report_lines.append("-"*40)
                for i in self.info_findings:
                    report_lines.append(f"\n  Type: {i['type']}")
                    report_lines.append(f"  Description: {i['description']}")
                    report_lines.append(f"  URL: {i['url']}")
                    if i.get('remediation'):
                        report_lines.append(f"  Recommendation: {i['remediation']}")
            
            # Add security recommendations based on findings
            if self.vulnerabilities:
                report_lines.append("\n" + "="*70)
                report_lines.append("SECURITY RECOMMENDATIONS:")
                report_lines.append("="*70)
                
                recommendations = set()
                for v in self.vulnerabilities:
                    if v.get('remediation'):
                        recommendations.add(v['remediation'])
                
                for i, rec in enumerate(recommendations, 1):
                    report_lines.append(f"{i}. {rec}")
            
            report_lines.append("\n" + "="*70)
            report_lines.append("SCAN COMPLETE - REMEMBER TO REMOVE THIS TOOL AFTER USE")
            report_lines.append("="*70)
            
            return '\n'.join(report_lines)

def main():
    parser = argparse.ArgumentParser(
        description='MyBB Security Assessment Tool - Enhanced Edition - For authorized testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python %(prog)s -u https://example.com/forum
  python %(prog)s -u https://example.com/forum -t 20 -d 3 -o report.txt
  python %(prog)s -u https://example.com/forum -f json -o report.json --proxy http://127.0.0.1:8080
  
WARNING: This tool can detect sensitive information including:
  - Database dumps and user credentials
  - Password hashes and salts
  - Email addresses and IPs
  - Backup files and configuration data
  
Only use on systems you OWN or have EXPLICIT WRITTEN PERMISSION to test.
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target MyBB URL (e.g., https://example.com/forum)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Scan depth (default: 2)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Report format (default: text)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates (default: False)')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip some heavy checks)')
    
    args = parser.parse_args()
    
    # Display enhanced disclaimer
    print(Fore.RED + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════════╗
║                     LEGAL DISCLAIMER                             ║
╠══════════════════════════════════════════════════════════════════╣
║  This tool is for AUTHORIZED SECURITY TESTING ONLY.              ║
║                                                                  ║
║  By using this tool, you confirm that:                           ║
║  1. You have EXPLICIT WRITTEN PERMISSION to test this target     ║
║  2. You are complying with all applicable laws and regulations   ║
║  3. You will responsibly disclose any findings to the owner      ║
║  4. You will NOT use this tool for any illegal purposes          ║
║                                                                  ║
║  Unauthorized use is ILLEGAL and UNETHICAL.                      ║
║  The developers assume NO LIABILITY for misuse.                  ║
╚══════════════════════════════════════════════════════════════════╝
    """ + Style.RESET_ALL)
    
    # Get confirmation with multiple checks
    print(Fore.YELLOW + f"Target: {args.url}" + Style.RESET_ALL)
    print()
    
    response1 = input("Do you have explicit written permission to test this target? (yes/no): ").lower()
    if response1 != 'yes':
        print(Fore.RED + "Exiting. Written permission is required." + Style.RESET_ALL)
        sys.exit(1)
    
    response2 = input("Are you sure this is a legitimate authorized test? (yes/no): ").lower()
    if response2 != 'yes':
        print(Fore.RED + "Exiting. Please confirm authorization." + Style.RESET_ALL)
        sys.exit(1)
    
    print(Fore.GREEN + f"\nStarting enhanced assessment of {args.url} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + Style.RESET_ALL)
    print(Fore.YELLOW + "WARNING: This scan may trigger security alerts and IDS systems" + Style.RESET_ALL)
    print()
    
    # Initialize scanner
    scanner = MyBBSecurityTester(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        proxy=args.proxy,
        depth=args.depth
    )
    
    # Run scan based on mode
    if args.quick:
        scanner.run_quick_scan()
    else:
        scanner.run_full_scan()
    
    # Generate and save report
    report = scanner.generate_report(args.format)
    
    # Print report
    print(report)
    
    # Save to file if output specified
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(Fore.GREEN + f"\n[+] Report saved to: {args.output}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[-] Error saving report: {e}" + Style.RESET_ALL)
    
    print(Fore.GREEN + f"\n[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Scan interrupted by user" + Style.RESET_ALL)
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[-] Unexpected error: {e}" + Style.RESET_ALL)
        sys.exit(1)
