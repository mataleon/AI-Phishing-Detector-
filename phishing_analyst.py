
import anthropic
import os
import re
from dotenv import load_dotenv

load_dotenv()


class PhishingAnalyst:
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.model  = "claude-sonnet-4-5-20250929"

    def analyze(self, parsed_email: dict, vt_results: dict, vt_summary: str) -> dict:
        headers = parsed_email.get("headers", {})
        body    = parsed_email.get("body", "")[:2000]
        urls    = parsed_email.get("urls", [])
        iocs    = parsed_email.get("iocs", {})

        prompt = f"""You are an expert email security analyst with 10 years of experience investigating phishing attacks.

Analyze this email and provide a detailed threat assessment.

EMAIL HEADERS:
{self._fmt(headers)}

EMAIL BODY (first 2000 chars):
{body}

EXTRACTED URLs:
{chr(10).join(urls) if urls else "None found"}

EXTRACTED IOCs:
- IPs: {', '.join(iocs.get('ips', [])) or 'None'}
- Domains: {', '.join(iocs.get('domains', [])) or 'None'}
- Hashes: {', '.join(iocs.get('hashes', [])) or 'None'}

VIRUSTOTAL RESULTS:
{vt_summary or 'No VT results available'}

You MUST start your response with these three lines exactly:
CLASSIFICATION: PHISHING
CONFIDENCE: High
PHISHING_PROBABILITY: 97

Then continue with:

## EXECUTIVE SUMMARY
[2-3 sentences describing what this email is and the threat it poses]

## PHISHING INDICATORS
[List each red flag found — be specific with evidence from the email]

## SOCIAL ENGINEERING TACTICS
[What psychological techniques are being used — urgency, fear, impersonation, etc.]

## TECHNICAL ANALYSIS
### Header Analysis
[What the headers reveal — spoofing, relay chains, anomalies]
### URL Analysis
[Analysis of each suspicious URL — typosquatting, redirect chains, etc.]
### IOC Analysis
[Assessment of IPs, domains found]

## IMPERSONATION ASSESSMENT
[Who is being impersonated and how convincingly]

## MITRE ATT&CK MAPPING
[Relevant techniques — T1566.001 Spearphishing, T1598 etc.]

## RECOMMENDED ACTIONS
- Immediate: [what to do right now]
- User Guidance: [what to tell the recipient]
- Technical: [blocks, rules, detections to implement]

## IOC SUMMARY
IPs: {', '.join(iocs.get('ips', [])) or 'None'}
Domains: {', '.join(iocs.get('domains', [])) or 'None'}
URLs: {', '.join(urls[:5]) or 'None'}"""

        message = self.client.messages.create(
            model=self.model,
            max_tokens=2500,
            messages=[{"role": "user", "content": prompt}]
        )

        analysis_text = message.content[0].text
        verdict = self._parse_verdict(analysis_text)
        verdict["full_analysis"] = analysis_text
        return verdict

    def _parse_verdict(self, text: str) -> dict:
        result = {
            "classification": "UNKNOWN",
            "confidence":     "Low",
            "probability":    0
        }

        # Flexible classification match
        class_match = re.search(
            r'CLASSIFICATION[:\s*_]+\**(PHISHING|SUSPICIOUS|LEGITIMATE|UNKNOWN)\**',
            text, re.I
        )
        if class_match:
            result["classification"] = class_match.group(1).upper()

        # Flexible confidence match
        conf_match = re.search(
            r'CONFIDENCE[:\s*_]+\**(High|Medium|Low)\**',
            text, re.I
        )
        if conf_match:
            result["confidence"] = conf_match.group(1).capitalize()

        # Flexible probability match
        prob_match = re.search(
            r'PHISHING[_\s]PROBABILITY[:\s*_]+\**(\d+)',
            text, re.I
        )
        if prob_match:
            result["probability"] = int(prob_match.group(1))

        return result

    def _fmt(self, d: dict) -> str:
        return "\n".join(f"  {k}: {v}" for k, v in d.items()) if d else "  No headers extracted"