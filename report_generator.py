import os
from datetime import datetime


class PhishingReportGenerator:
    def __init__(self):
        os.makedirs("reports", exist_ok=True)

    def save_report(self, parsed_email: dict, verdict: dict) -> str:
        subject = parsed_email.get("headers", {}).get("Subject", "Unknown Subject")
        sender  = parsed_email.get("headers", {}).get("From", "Unknown Sender")
        classification = verdict.get("classification", "UNKNOWN")
        probability    = verdict.get("probability", 0)
        confidence     = verdict.get("confidence", "Low")
        analysis       = verdict.get("full_analysis", "")
        timestamp      = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename       = f"reports/phishing_report_{timestamp}.md"

        report = f"""# Phishing Analysis Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Email Information
| Field | Value |
|-------|-------|
| Subject | {subject} |
| From | {sender} |
| Classification | {classification} |
| Phishing Probability | {probability}% |
| Confidence | {confidence} |

## Analysis

{analysis}

---
Powered by Claude AI + VirusTotal
"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"  Report saved: {filename}")
        return filename

    def save_html_report(self, parsed_email: dict, verdict: dict) -> str:
        subject        = parsed_email.get("headers", {}).get("Subject", "Unknown Subject")
        sender         = parsed_email.get("headers", {}).get("From", "Unknown Sender")
        classification = verdict.get("classification", "UNKNOWN")
        probability    = verdict.get("probability", 0)
        confidence     = verdict.get("confidence", "Low")
        analysis       = verdict.get("full_analysis", "").replace("\n", "<br>")
        iocs           = parsed_email.get("iocs", {})
        timestamp      = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename       = f"reports/phishing_report_{timestamp}.html"

        colours = {
            "PHISHING":   ("#dc3545", "#fff"),
            "SUSPICIOUS": ("#fd7e14", "#fff"),
            "LEGITIMATE": ("#28a745", "#fff"),
            "UNKNOWN":    ("#6c757d", "#fff"),
        }
        bg, fg = colours.get(classification, ("#6c757d", "#fff"))

        bar_colour = "#dc3545" if probability >= 70 else "#fd7e14" if probability >= 40 else "#28a745"

        ioc_rows = ""
        for ip in iocs.get("ips", []):
            ioc_rows += f"<tr><td>IP</td><td>{ip}</td></tr>"
        for d in iocs.get("domains", []):
            ioc_rows += f"<tr><td>Domain</td><td>{d}</td></tr>"
        for u in iocs.get("urls", [])[:5]:
            ioc_rows += f"<tr><td>URL</td><td style='word-break:break-all'>{u}</td></tr>"

        html = f"""<!DOCTYPE html>
<html>
<head>
  <title>Phishing Report — {subject}</title>
  <meta charset="utf-8">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 24px; margin-bottom: 20px; }}
    .header {{ background: #1f2937; border-radius: 10px; padding: 24px; margin-bottom: 20px; border-left: 5px solid {bg}; }}
    h1 {{ color: #e6edf3; font-size: 22px; margin-bottom: 8px; }}
    h2 {{ color: #8b949e; font-size: 13px; font-weight: normal; margin-bottom: 20px; }}
    .badge {{ display: inline-block; background: {bg}; color: {fg}; padding: 6px 16px; border-radius: 20px; font-weight: bold; font-size: 14px; }}
    .prob-bar {{ background: #21262d; border-radius: 8px; height: 12px; margin: 10px 0; overflow: hidden; }}
    .prob-fill {{ height: 100%; background: {bar_colour}; width: {probability}%; border-radius: 8px; transition: width 1s; }}
    .prob-label {{ font-size: 28px; font-weight: bold; color: {bar_colour}; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #21262d; }}
    th {{ color: #8b949e; font-weight: 500; }}
    .analysis {{ background: #161b22; border-radius: 10px; padding: 24px; font-size: 14px; line-height: 1.8; color: #c9d1d9; }}
    .footer {{ text-align: center; color: #484f58; font-size: 12px; margin-top: 30px; }}
  </style>
</head>
<body>

  <div class="header">
    <h1>🔍 AI Phishing Analysis Report</h1>
    <h2>Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} · Powered by Claude AI + VirusTotal</h2>
    <span class="badge">{classification}</span>
  </div>

  <div class="card">
    <table>
      <tr><th>Subject</th><td>{subject}</td></tr>
      <tr><th>From</th><td>{sender}</td></tr>
      <tr><th>Confidence</th><td>{confidence}</td></tr>
    </table>
    <br>
    <div class="prob-label">{probability}%</div>
    <div style="color:#8b949e;font-size:13px;margin-bottom:6px">Phishing Probability</div>
    <div class="prob-bar"><div class="prob-fill"></div></div>
  </div>

  {'<div class="card"><h3 style="color:#8b949e;margin-bottom:12px;font-size:13px">EXTRACTED IOCs</h3><table><tr><th>Type</th><th>Value</th></tr>' + ioc_rows + '</table></div>' if ioc_rows else ''}

  <div class="analysis">{analysis}</div>

  <div class="footer">Powered by Claude AI + VirusTotal · AI Phishing Detector</div>
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  HTML report saved: {filename}")
        return filename
