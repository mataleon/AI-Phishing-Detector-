import os
import sys
from email_parser import EmailParser
from vt_client import VTClient
from phishing_analyst import PhishingAnalyst
from report_generator import PhishingReportGenerator

VERDICT_COLOURS = {
    "PHISHING":   "\033[91m",
    "SUSPICIOUS": "\033[93m",
    "LEGITIMATE": "\033[92m",
    "UNKNOWN":    "\033[94m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"

# Built-in sample phishing email for testing without a real file
SAMPLE_EMAIL = """From: security-alert@paypa1-support.com
To: victim@company.com
Subject: URGENT: Your PayPal account has been suspended
Date: Mon, 25 May 2026 03:00:00 +0000
Reply-To: noreply@paypa1-support.com
X-Originating-IP: 185.220.101.47
Message-ID: <fake123@paypa1-support.com>

Dear Valued Customer,

We have detected SUSPICIOUS ACTIVITY on your PayPal account.
Your account has been TEMPORARILY SUSPENDED for security reasons.

You must verify your identity within 24 HOURS or your account
will be permanently closed and funds withheld.

Click here immediately to verify: http://paypa1-secure-login.ru/verify?id=victim@company.com

If you do not verify within 24 hours:
- Your account will be permanently suspended
- Your funds ($3,847.23) will be frozen
- Legal action may be pursued

Verify Now: http://185.220.101.47/paypal/login.php

PayPal Security Team
Case ID: PP-8847221-SUSPENDED
"""


def print_banner():
    print("\n" + "="*60)
    print(f"  {BOLD}AI PHISHING DETECTOR{RESET}")
    print("  Powered by Claude AI + VirusTotal")
    print("="*60 + "\n")


def print_verdict(verdict: dict):
    classification = verdict.get("classification", "UNKNOWN")
    probability    = verdict.get("probability", 0)
    confidence     = verdict.get("confidence", "Low")
    colour         = VERDICT_COLOURS.get(classification, "")

    print(f"\n  {'─'*50}")
    print(f"  VERDICT:     {colour}{BOLD}{classification}{RESET}")
    print(f"  PROBABILITY: {colour}{probability}%{RESET}")
    print(f"  CONFIDENCE:  {confidence}")
    print(f"  {'─'*50}\n")


def analyze_email(raw_email: str, skip_vt: bool = False):
    parser   = EmailParser()
    analyst  = PhishingAnalyst()
    reporter = PhishingReportGenerator()
    vt       = VTClient() if not skip_vt else None

    print("  [1/4] Parsing email...")
    parsed = parser.parse_raw(raw_email)
    iocs   = parsed.get("iocs", {})
    print(f"         Subject : {parsed['headers'].get('Subject', 'N/A')}")
    print(f"         From    : {parsed['headers'].get('From', 'N/A')}")
    print(f"         URLs    : {len(parsed['urls'])} found")
    print(f"         IOCs    : {len(iocs['ips'])} IPs, {len(iocs['domains'])} domains")

    vt_results = {}
    vt_summary = ""
    if vt and (iocs["ips"] or iocs["domains"]):
        print("\n  [2/4] Checking IOCs against VirusTotal...")
        print("         (free tier: 15s delay between lookups)")
        vt_results = vt.scan_iocs(iocs, max_per_type=2)
        vt_summary = vt.summarise_results(vt_results)
    else:
        print("\n  [2/4] Skipping VirusTotal (--no-vt flag or no IOCs)")

    print("\n  [3/4] Running AI analysis...")
    verdict = analyst.analyze(parsed, vt_results, vt_summary)
    print("         Analysis complete")

    print("\n  [4/4] Saving reports...")
    reporter.save_report(parsed, verdict)
    reporter.save_html_report(parsed, verdict)

    print_verdict(verdict)
    return verdict


def main():
    print_banner()

    skip_vt = "--no-vt" in sys.argv
    sample  = "--sample" in sys.argv or "-s" in sys.argv

    # Get email file from args
    email_file = None
    for arg in sys.argv[1:]:
        if not arg.startswith("-") and arg.endswith((".eml", ".txt", ".msg")):
            email_file = arg
            break

    if sample:
        print("  Using built-in sample phishing email...\n")
        analyze_email(SAMPLE_EMAIL, skip_vt=skip_vt)

    elif email_file:
        if not os.path.exists(email_file):
            print(f"  Error: File not found — {email_file}")
            sys.exit(1)
        print(f"  Analysing: {email_file}\n")
        with open(email_file, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        analyze_email(raw, skip_vt=skip_vt)

    else:
        print("Usage:")
        print("  python main.py --sample              # test with built-in phishing email")
        print("  python main.py --sample --no-vt      # skip VirusTotal (faster)")
        print("  python main.py email.eml             # analyse a real .eml file")
        print("  python main.py email.eml --no-vt     # analyse without VT lookup")
        print()
        print("Set environment variables:")
        print("  ANTHROPIC_API_KEY   — your Anthropic key")
        print("  VIRUSTOTAL_API_KEY  — your VirusTotal key (optional with --no-vt)")


if __name__ == "__main__":
    main()
