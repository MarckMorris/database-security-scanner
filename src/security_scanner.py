#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database Security Scanner
Scans for vulnerabilities and compliance issues
"""

import psycopg2
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class SecurityScanner:
    
    def __init__(self):
        self.conn = None
        self.findings = []
        
    def connect(self):
        try:
            self.conn = psycopg2.connect(
                host='localhost', port=5458,
                dbname='target_db', user='postgres', password='postgres'
            )
            self.conn.autocommit = True
            logger.info("Connected to target database")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def setup_target_db(self):
        logger.info("Setting up target database...")
        
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                username VARCHAR(100),
                password VARCHAR(100),
                email VARCHAR(100),
                role VARCHAR(50)
            );
            
            CREATE TABLE IF NOT EXISTS sensitive_data (
                data_id SERIAL PRIMARY KEY,
                ssn VARCHAR(11),
                credit_card VARCHAR(16),
                data TEXT
            );
            
            INSERT INTO users (username, password, email, role)
            VALUES 
                ('admin', 'admin123', 'admin@test.com', 'admin'),
                ('user1', 'password', 'user1@test.com', 'user')
            ON CONFLICT DO NOTHING;
        """)
        cursor.close()
        logger.info("Target database ready")
    
    def add_finding(self, category: str, severity: str, title: str, 
                    description: str, recommendation: str):
        self.findings.append({
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'timestamp': datetime.now()
        })
    
    def scan_weak_passwords(self):
        logger.info("Scanning for weak passwords...")
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'password'
        """)
        
        if cursor.fetchone():
            self.add_finding(
                category='Authentication',
                severity='critical',
                title='Plaintext Password Storage',
                description='Passwords are stored in plaintext',
                recommendation='Use bcrypt or Argon2 for password hashing'
            )
            
            cursor.execute("""
                SELECT username, password 
                FROM users 
                WHERE password IN ('admin', 'password', 'admin123', '123456')
            """)
            
            weak_passwords = cursor.fetchall()
            if weak_passwords:
                self.add_finding(
                    category='Authentication',
                    severity='high',
                    title='Weak Default Passwords',
                    description=f'Found {len(weak_passwords)} user(s) with weak passwords',
                    recommendation='Enforce strong password policy'
                )
        
        cursor.close()
    
    def scan_encryption(self):
        logger.info("Scanning encryption...")
        
        cursor = self.conn.cursor()
        cursor.execute("SHOW ssl")
        ssl_enabled = cursor.fetchone()[0]
        
        if ssl_enabled != 'on':
            self.add_finding(
                category='Encryption',
                severity='critical',
                title='SSL/TLS Not Enabled',
                description='Database connections are not encrypted',
                recommendation='Enable SSL in postgresql.conf'
            )
        
        cursor.close()
    
    def scan_access_controls(self):
        logger.info("Scanning access controls...")
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT grantee, privilege_type 
            FROM information_schema.table_privileges 
            WHERE grantee = 'PUBLIC'
        """)
        
        public_privs = cursor.fetchall()
        if public_privs:
            self.add_finding(
                category='Access Control',
                severity='high',
                title='Excessive PUBLIC Privileges',
                description=f'PUBLIC role has {len(public_privs)} privileges',
                recommendation='Revoke unnecessary PUBLIC privileges'
            )
        
        cursor.close()
    
    def scan_sensitive_data(self):
        logger.info("Scanning for sensitive data...")
        
        cursor = self.conn.cursor()
        sensitive_columns = ['ssn', 'credit_card', 'password']
        
        for col in sensitive_columns:
            cursor.execute(f"""
                SELECT table_name, column_name 
                FROM information_schema.columns 
                WHERE column_name LIKE '%{col}%'
            """)
            
            results = cursor.fetchall()
            if results:
                for table, column in results:
                    self.add_finding(
                        category='Data Protection',
                        severity='high',
                        title=f'Unencrypted Sensitive Column: {table}.{column}',
                        description=f'Column {column} may contain sensitive data',
                        recommendation='Implement column-level encryption'
                    )
        
        cursor.close()
    
    def scan_audit_logging(self):
        logger.info("Scanning audit logging...")
        
        cursor = self.conn.cursor()
        cursor.execute("SHOW log_statement")
        log_statement = cursor.fetchone()[0]
        
        if log_statement not in ['all', 'ddl']:
            self.add_finding(
                category='Auditing',
                severity='medium',
                title='Insufficient Audit Logging',
                description=f'log_statement is "{log_statement}"',
                recommendation='Enable comprehensive logging'
            )
        
        cursor.close()
    
    def generate_report(self):
        print("\n" + "=" * 80)
        print("DATABASE SECURITY SCAN REPORT")
        print("=" * 80)
        print(f"Scan Date: {datetime.now()}")
        print(f"Total Findings: {len(self.findings)}")
        
        critical = [f for f in self.findings if f['severity'] == 'critical']
        high = [f for f in self.findings if f['severity'] == 'high']
        medium = [f for f in self.findings if f['severity'] == 'medium']
        
        print(f"\nSeverity Breakdown:")
        print(f"  Critical: {len(critical)}")
        print(f"  High: {len(high)}")
        print(f"  Medium: {len(medium)}")
        
        categories = {}
        for finding in self.findings:
            cat = finding['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(finding)
        
        print(f"\nFindings by Category:")
        for category, findings in sorted(categories.items()):
            print(f"  {category}: {len(findings)}")
        
        print("\n" + "=" * 80)
        print("DETAILED FINDINGS")
        print("=" * 80)
        
        for i, finding in enumerate(self.findings, 1):
            severity_marker = {
                'critical': '[CRITICAL]',
                'high': '[HIGH]',
                'medium': '[MEDIUM]'
            }.get(finding['severity'], '[INFO]')
            
            print(f"\n[{i}] {severity_marker} {finding['title']}")
            print(f"    Category: {finding['category']}")
            print(f"    Description: {finding['description']}")
            print(f"    Recommendation: {finding['recommendation']}")
        
        print("\n" + "=" * 80)
        print("COMPLIANCE SUMMARY")
        print("=" * 80)
        
        score = max(0, 100 - (len(critical) * 25 + len(high) * 10 + len(medium) * 5))
        print(f"Compliance Score: {score}/100")
        
        status = "PASS" if score >= 80 else "WARNING" if score >= 60 else "FAIL"
        print(f"Status: {status}")
        print("=" * 80)
    
    def run_scan(self):
        print("\n" + "=" * 80)
        print("DATABASE SECURITY SCANNER")
        print("=" * 80)
        
        if not self.connect():
            return
        
        self.setup_target_db()
        
        print("\nExecuting Security Scans...")
        self.scan_weak_passwords()
        self.scan_encryption()
        self.scan_access_controls()
        self.scan_sensitive_data()
        self.scan_audit_logging()
        
        logger.info(f"Scan complete - {len(self.findings)} findings")
        self.generate_report()


def main():
    scanner = SecurityScanner()
    scanner.run_scan()


if __name__ == "__main__":
    main()
