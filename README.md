AI Phishing Detector 🎣

Upload any suspicious email — AI analyses it, extracts IOCs, checks VirusTotal, and generates a professional threat report

An AI-powered phishing analysis tool that dissects suspicious emails, extracts indicators of compromise, cross-references them against VirusTotal, and produces a detailed threat report — in under 60 seconds.
97% phishing probability detected on first run. 0 false negatives on test cases.

What It Does

Parses email headers, body, URLs, and attachments
Extracts IOCs — IPs, domains, URLs, file hashes automatically
Checks VirusTotal — cross-references every IOC against 70+ security engines
AI analysis — Claude investigates social engineering tactics, header anomalies, spoofing, typosquatting
MITRE ATT&CK mapping — maps attack techniques automatically
Generates reports — professional HTML + Markdown threat reports


Demo
============================================================
  AI PHISHING DETECTOR
  Powered by Claude AI + VirusTotal
============================================================

  [1/4] Parsing email...
         Subject : URGENT: Your PayPal account has been suspended
         From    : security-alert@paypa1-support.com
         URLs    : 2 found
         IOCs    : 1 IPs, 2 domains

  [2/4] Checking IOCs against VirusTotal...
         Checking IP: 185.220.101.47
         Checking domain: paypa1-secure-login.ru

  [3/4] Running AI analysis...
         Analysis complete

  [4/4] Saving reports...
         Report saved: reports/phishing_report_20260525_154645.md
         HTML report  : reports/phishing_report_20260525_154645.html

  ──────────────────────────────────────────────────
  VERDICT:     PHISHING
  PROBABILITY: 97%
  CONFIDENCE:  High
  ──────────────────────────────────────────────────

Sample Report Output
## EXECUTIVE SUMMARY
This email is a PayPal impersonation phishing attack designed to steal
account credentials. The sender domain paypa1-support.com uses a
typosquatted domain replacing the letter 'l' with '1'. The email
employs classic urgency and fear tactics to pressure the victim into
clicking a malicious link hosted on a Russian IP address.

## PHISHING INDICATORS
- Typosquatted sender domain: paypa1-support.com (PayPal → Paypa1)
- Malicious URL: http://185.220.101.47/paypal/login.php (raw IP, not PayPal)
- Russian redirect domain: paypa1-secure-login.ru
- Urgency language: "URGENT", "24 HOURS", "permanently closed"
- Fear tactic: threatens frozen funds of $3,847.23
- Mismatched Reply-To domain

## MITRE ATT&CK MAPPING
- T1566.001 — Spearphishing Attachment
- T1598.003 — Phishing for Information
- T1036 — Masquerading (domain typosquatting)
- T1204.001 — User Execution: Malicious Link

## VIRUSTOTAL RESULTS
- IP 185.220.101.47: ⚠️ MALICIOUS — 14/87 engines flagged
- Domain paypa1-secure-login.ru: ⚠️ MALICIOUS — 9/87 engines flagged

Project Structure
ai-phishing-detector/
├── main.py               # Entry point — orchestrates full pipeline
├── email_parser.py       # Header, body, URL, IOC extraction
├── vt_client.py          # VirusTotal API integration
├── phishing_analyst.py   # Claude AI analysis engine
├── report_generator.py   # HTML + Markdown report generation
└── reports/              # Generated threat reports (auto-created)

Setup
1. Clone the repo
bashgit clone https://github.com/yourusername/ai-phishing-detector
cd ai-phishing-detector
2. Install dependencies
bashpip install anthropic requests python-dotenv
3. Get API keys
Anthropic: https://console.anthropic.com/settings/keys
VirusTotal (free):

Create account at https://www.virustotal.com
Profile → API Key → copy

4. Set environment variables
powershell# Windows PowerShell
$env:ANTHROPIC_API_KEY = "your-key"
$env:VIRUSTOTAL_API_KEY = "your-vt-key"
5. Run
bash# Test with built-in sample phishing email
python main.py --sample

# Skip VirusTotal for faster results
python main.py --sample --no-vt

# Analyse a real email file
python main.py suspicious_email.eml

# Analyse without VT lookup
python main.py suspicious_email.eml --no-vt

Supported Email Formats
FormatExtensionNotesRaw email.emlFull header + body parsingPlain text.txtBody analysis + IOC extractionOutlook export.msgHeader + body parsing

What Claude Analyses
CategoryWhat It Looks ForHeader AnalysisSPF/DKIM failures, relay chains, X-Originating-IP anomaliesDomain AnalysisTyposquatting, lookalike domains, newly registered domainsURL AnalysisRedirect chains, raw IP URLs, suspicious TLDsSocial EngineeringUrgency, fear, authority impersonation, pressure tacticsImpersonationBrand spoofing, executive impersonation, IT helpdesk scamsIOC ExtractionIPs, domains, URLs, file hashes for threat intel feeds

Environment Variables
VariableRequiredDescriptionANTHROPIC_API_KEY✅ YesYour Anthropic API keyVIRUSTOTAL_API_KEY⚠️ OptionalVirusTotal API key (use --no-vt to skip
The Full Story
This project is part of a hands-on cybersecurity portfolio built from scratch:

Deployed a honeypot — collected 200,000+ real attack events
Built an Active Directory lab — simulated enterprise environment
Configured Microsoft Sentinel — detection rules for APT techniques
Built an AI SOC Analyst — automated Tier 1 investigation workflow
Built an LLM Injection Defender — 17/17 attack types detected
Built this AI Phishing Detector — full IOC extraction + VT integrat
