import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

VT_BASE = "https://www.virustotal.com/api/v3"


class VTClient:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": self.api_key}
        self.delay   = 15  # free tier: 4 requests/min

    def check_ip(self, ip: str) -> dict:
        return self._query(f"{VT_BASE}/ip_addresses/{ip}", f"IP:{ip}")

    def check_domain(self, domain: str) -> dict:
        return self._query(f"{VT_BASE}/domains/{domain}", f"Domain:{domain}")

    def check_url(self, url: str) -> dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._query(f"{VT_BASE}/urls/{url_id}", f"URL:{url}")

    def check_hash(self, file_hash: str) -> dict:
        return self._query(f"{VT_BASE}/files/{file_hash}", f"Hash:{file_hash}")

    def scan_iocs(self, iocs: dict, max_per_type: int = 3) -> dict:
        results = {}

        for ip in iocs.get("ips", [])[:max_per_type]:
            print(f"    Checking IP: {ip}")
            results[f"ip:{ip}"] = self.check_ip(ip)
            time.sleep(self.delay)

        for domain in iocs.get("domains", [])[:max_per_type]:
            print(f"    Checking domain: {domain}")
            results[f"domain:{domain}"] = self.check_domain(domain)
            time.sleep(self.delay)

        for h in iocs.get("hashes", [])[:max_per_type]:
            print(f"    Checking hash: {h[:16]}...")
            results[f"hash:{h}"] = self.check_hash(h)
            time.sleep(self.delay)

        return results

    def _query(self, url: str, label: str) -> dict:
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                data  = r.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "label":       label,
                    "malicious":   stats.get("malicious", 0),
                    "suspicious":  stats.get("suspicious", 0),
                    "clean":       stats.get("undetected", 0),
                    "total":       sum(stats.values()),
                    "reputation":  attrs.get("reputation", "N/A"),
                    "country":     attrs.get("country", "Unknown"),
                    "status":      "found"
                }
            elif r.status_code == 404:
                return {"label": label, "status": "not_found", "malicious": 0}
            elif r.status_code == 429:
                return {"label": label, "status": "rate_limited", "malicious": 0}
            else:
                return {"label": label, "status": f"error_{r.status_code}", "malicious": 0}
        except Exception as e:
            return {"label": label, "status": f"exception:{e}", "malicious": 0}

    def summarise_results(self, vt_results: dict) -> str:
        if not vt_results:
            return "No IOCs checked against VirusTotal."

        lines = []
        for key, res in vt_results.items():
            label     = res.get("label", key)
            status    = res.get("status", "unknown")
            malicious = res.get("malicious", 0)
            total     = res.get("total", 0)

            if status == "not_found":
                lines.append(f"- {label}: Not found in VT database")
            elif status == "rate_limited":
                lines.append(f"- {label}: Rate limited — check manually")
            elif malicious > 0:
                lines.append(f"- {label}: ⚠️  MALICIOUS — {malicious}/{total} engines flagged")
            else:
                lines.append(f"- {label}: Clean ({total} engines checked)")
        return "\n".join(lines)
