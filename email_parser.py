import re
import email
from email import policy
from urllib.parse import urlparse


class EmailParser:
    def __init__(self):
        self.ip_pattern    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        self.hash_pattern  = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        self.url_pattern   = re.compile(
            r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
        )

    def parse_file(self, filepath: str) -> dict:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        return self.parse_raw(raw)

    def parse_raw(self, raw_email: str) -> dict:
        try:
            msg = email.message_from_string(raw_email, policy=policy.default)
        except Exception:
            msg = None

        headers = self._extract_headers(msg, raw_email)
        body    = self._extract_body(msg, raw_email)
        urls    = self._extract_urls(body + " " + raw_email)
        iocs    = self._extract_iocs(body, urls, raw_email)

        return {
            "headers":     headers,
            "body":        body[:3000],
            "urls":        urls,
            "iocs":        iocs,
            "raw_preview": raw_email[:500]
        }

    def _extract_headers(self, msg, raw: str) -> dict:
        headers = {}
        if msg:
            for key in ["From", "To", "Subject", "Date", "Reply-To",
                        "Return-Path", "Received", "X-Originating-IP",
                        "X-Mailer", "Message-ID", "DKIM-Signature",
                        "Authentication-Results", "X-Spam-Status"]:
                val = msg.get(key)
                if val:
                    headers[key] = str(val)
        else:
            # Fallback: regex header extraction
            for line in raw.split("\n")[:40]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
        return headers

    def _extract_body(self, msg, raw: str) -> str:
        if not msg:
            return raw

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    try:
                        body += part.get_content() + "\n"
                    except Exception:
                        pass
        else:
            try:
                body = msg.get_content()
            except Exception:
                body = raw
        return body

    def _extract_urls(self, text: str) -> list:
        found = self.url_pattern.findall(text)
        cleaned = []
        seen = set()
        for url in found:
            url = url.rstrip(".,;)")
            if url not in seen:
                seen.add(url)
                cleaned.append(url)
        return cleaned[:20]  # cap at 20

    def _extract_iocs(self, body: str, urls: list, raw: str) -> dict:
        combined = body + " " + raw

        # IPs
        ips = list(set(self.ip_pattern.findall(combined)))
        # Filter private/loopback
        ips = [ip for ip in ips if not (
            ip.startswith("127.") or ip.startswith("192.168.") or
            ip.startswith("10.") or ip.startswith("172.") or ip == "0.0.0.0"
        )]

        # Domains from URLs
        domains = []
        seen_d = set()
        for url in urls:
            try:
                d = urlparse(url).netloc
                if d and d not in seen_d:
                    seen_d.add(d)
                    domains.append(d)
            except Exception:
                pass

        # Hashes
        hashes = list(set(self.hash_pattern.findall(combined)))
        hashes = [h for h in hashes if len(h) in (32, 40, 64)]

        return {
            "ips":     ips[:10],
            "domains": domains[:10],
            "hashes":  hashes[:10],
            "urls":    urls[:10]
        }
