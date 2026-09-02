#!/usr/bin/env python3
import argparse
import sys
import os
import platform
import logging

# Ensure the root project directory is in the python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import AuditEngine
from core.reporter import AuditReporter

def print_banner():
    banner = """
    ==================================================
      [+] PrivEscAuditor - Local Privilege Escalation Audit
    ==================================================
    """
    print(banner)


def main():
    parser = argparse.ArgumentParser(description="PrivEscAuditor: Local Privilege Escalation Auditing Tool")
    parser.add_argument("-o", "--html", default="report.html", help="Path to write the HTML report (default: report.html)")
    parser.add_argument("-j", "--json", default="report.json", help="Path to write the JSON data (default: report.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging output")
    
    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    print_banner()
    
    # Initialize and run the audit engine
    engine = AuditEngine()
    engine.load_checks()
    
    if not engine.checks:
        print("[-] No checks loaded for this operating system. Exiting.")
        sys.exit(1)

    print(f"[*] Starting audit scan on {platform.node()} ({platform.system()} {platform.release()})...")
    print(f"[*] Running {len(engine.checks)} security audit checks.")
    print("-" * 65)

    results = engine.run_all()
    
    print("-" * 65)
    print("\n[+] Audit Scan Complete!")
    print("\nCheck Results Summary:")
    print(f"{'Check Name':<45} | {'Severity':<10} | {'Status':<10}")
    print("-" * 72)
    
    # Print console summary
    triggered_count = 0
    for r in results:
        status_str = "TRIGGERED" if r.triggered else "PASSED"
        if r.triggered:
            triggered_count += 1
            # Color triggered results red if console supports it, or just use ASCII marks
            print(f"[!] {r.check_name:<42} | {r.severity:<10} | \033[91m{status_str:<10}\033[0m")
        else:
            print(f"[+] {r.check_name:<42} | {r.severity:<10} | \033[92m{status_str:<10}\033[0m")


    # Generate Reports
    reporter = AuditReporter(results)
    
    html_path = os.path.abspath(args.html)
    json_path = os.path.abspath(args.json)
    
    reporter.generate_html(html_path)
    reporter.generate_json(json_path)
    
    print("-" * 72)
    print(f"[+] HTML Report generated: {html_path}")
    print(f"[+] JSON Data generated: {json_path}")
    print(f"[+] Total triggered vulnerabilities/warnings: {triggered_count}")
    print("==================================================")

if __name__ == "__main__":
    main()
