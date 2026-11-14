#!/usr/bin/env python3
"""
Phishing Email Clue Checker
---------------------------
A simple WARNING system (not a blocker) that scans an email for common
phishing clues and tells the user to be cautious.

Checks (matches the project methodology):
  1. Text clues      - impersonal greeting ("Hello User"), urgency, requests
                       for credentials, threats, loose grammar/style hints
  2. Link clues      - link domain doesn't match sender domain, very long
                       links, IP-address links, URL shorteners, '@' tricks,
                       link text that shows a different site than where it goes
  3. Sender clues    - look-alike domains ("rnicrosoft"), Reply-To mismatch,
                       failed SPF/DKIM results in the headers

Usage:
  python phishing_checker.py message.eml      # check a saved email (.eml)
  python phishing_checker.py --demo           # run built-in sample emails
"""

import argparse
import re
import sys
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Clue lists (easy to extend)
# --------------------------------------------------------------------------

GENERIC_GREETINGS = re.compile(
    r"^\s*(hello|hi|hey|dear|greetings)[\s,]+"
    r"(user|customer|client|member|valued customer|valued member|account holder|"
    r"sir|madam|sir/madam|friend|email user|webmail user|employee|beneficiary)\b",
    re.IGNORECASE,
)

URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "right away", "as soon as possible",
    "within 24 hours", "within 48 hours", "final notice", "last warning",
    "expires today", "account will be suspended", "account will be closed",
    "your account has been suspended", "limited time", "failure to comply",
    "action required", "respond immediately",
]

INFO_REQUEST_PHRASES = [
    "verify your account", "confirm your password", "confirm your identity",
    "update your payment", "update your billing", "enter your password",
    "login to verify", "click here to", "re-activate your account",
    "reactivate your account", "validate your account", "social security",
    "bank details", "credit card number",
]

# Common misspellings seen in scam emails (a loose guideline only!)
COMMON_MISTAKES = [
    "kindly do the needful", "recieve", "acount", "verfiy", "securty",
    "pasword", "informations", "dear costumer", "your account have been",
    "we have notice", "click the link bellow",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

# Brands that attackers like to imitate
KNOWN_BRANDS = [
    "microsoft", "paypal", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "revolut", "dropbox", "linkedin", "docusign",
]

LONG_URL_LENGTH = 75
URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Points per finding -> overall risk level
WEIGHTS = {"high": 3, "medium": 2, "low": 1}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Pulls (href, visible_text) pairs out of HTML and strips tags to text."""

    def __init__(self):
        super().__init__()
        self.links = []          # [(href, text)]
        self.text_parts = []
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current_href = dict(attrs).get("href")
            self._current_text = []

    def handle_data(self, data):
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None


def registered_domain(host: str) -> str:
    """Rough 'example.com' from 'mail.example.com' (handles .co.uk style)."""
    host = host.lower().strip(".")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):  # raw IP: leave as-is
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in {"co", "com", "org", "ac", "gov", "net"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def normalise_lookalikes(domain: str) -> str:
    """Undo common character swaps: rn->m, 0->o, 1->l, vv->w."""
    d = domain.lower()
    d = d.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "l")
    return d


def extract_email_parts(msg):
    """Return (plain_text_body, [(href, text)], raw_html_present)."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not plain:
                plain = part.get_content()
            elif ctype == "text/html" and not html:
                html = part.get_content()
    else:
        content = msg.get_content()
        if msg.get_content_type() == "text/html":
            html = content
        else:
            plain = content

    links = []
    if html:
        extractor = _LinkExtractor()
        extractor.feed(html)
        links.extend(extractor.links)
        if not plain:
            plain = " ".join(extractor.text_parts)

    # Also catch bare URLs in the plain text
    for url in URL_REGEX.findall(plain or ""):
        links.append((url, url))

    return plain or "", links


# --------------------------------------------------------------------------
# The three checks
# --------------------------------------------------------------------------

def check_text(subject: str, body: str):
    findings = []
    full = f"{subject}\n{body}".lower()

    if GENERIC_GREETINGS.search(body):
        findings.append(("medium", 'Impersonal greeting (e.g. "Hello User") - '
                                   "real senders usually use your name."))

    urgent = [p for p in URGENCY_PHRASES if p in full]
    if urgent:
        findings.append(("medium", "Urgent/pressuring language: "
                                   + ", ".join(f'"{p}"' for p in urgent[:4])))

    asks = [p for p in INFO_REQUEST_PHRASES if p in full]
    if asks:
        findings.append(("medium", "Asks you to verify/confirm/enter details: "
                                   + ", ".join(f'"{p}"' for p in asks[:4])))

    # Loose style/grammar hints - low weight, as the project notes say
    mistakes = [m for m in COMMON_MISTAKES if m in full]
    if mistakes:
        findings.append(("low", "Possible spelling/grammar slips: "
                                + ", ".join(f'"{m}"' for m in mistakes[:3])))
    if re.search(r"[!?]{2,}", body):
        findings.append(("low", "Excessive punctuation (!! or ??)."))
    shouting = re.findall(r"\b[A-Z]{5,}\b", body)
    if len(shouting) >= 3:
        findings.append(("low", "Lots of ALL-CAPS words."))

    return findings


def check_links(sender_domain: str, links):
    findings = []
    seen = set()

    for href, text in links:
        if not href or href in seen or href.startswith(("mailto:", "#")):
            continue
        seen.add(href)
        host = host_of(href)
        if not host:
            continue
        link_dom = registered_domain(host)
        short = href if len(href) <= 60 else href[:57] + "..."

        # Core rule from the methodology: link should match the sender's domain
        if sender_domain and link_dom != sender_domain:
            findings.append(("high", f"Link goes to '{link_dom}', which does not match "
                                     f"the sender's domain '{sender_domain}': {short}"))

        if len(href) > LONG_URL_LENGTH:
            findings.append(("low", f"Unusually long link ({len(href)} characters): {short}"))

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            findings.append(("high", f"Link uses a raw IP address instead of a domain: {short}"))

        if link_dom in URL_SHORTENERS:
            findings.append(("medium", f"Link uses a URL shortener that hides the real "
                                       f"destination: {short}"))

        if "@" in urlparse(href).netloc:
            findings.append(("high", f"Link contains '@' (a trick to disguise the real "
                                     f"host): {short}"))

        if "xn--" in host:
            findings.append(("medium", f"Link uses punycode (possible look-alike "
                                       f"characters): {short}"))

        if host.count(".") >= 4:
            findings.append(("low", f"Link has many sub-domains: {host}"))

        # Visible text says one site, link goes to another
        shown = URL_REGEX.search(text or "") or re.search(
            r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", (text or "").lower())
        if shown and text != href:
            shown_host = host_of(shown.group(0)) or shown.group(0).lower()
            if registered_domain(shown_host) != link_dom:
                findings.append(("high", f"Link text shows '{shown_host}' but actually "
                                         f"goes to '{link_dom}'."))

    return findings


def check_sender(msg, sender_domain: str):
    findings = []

    # Look-alike of a well-known brand, e.g. rnicrosoft
    if sender_domain:
        label = sender_domain.split(".")[0]
        fixed = normalise_lookalikes(sender_domain)
        for brand in KNOWN_BRANDS:
            if brand in fixed and brand not in sender_domain.lower():
                findings.append(("high", f"Sender domain '{sender_domain}' looks like a "
                                         f"fake of '{brand}' (character swap such as rn -> m)."))
                break
        else:
            # Brand name used inside a different domain, e.g. paypal-security.com
            for brand in KNOWN_BRANDS:
                if brand in label and label != brand:
                    findings.append(("medium", f"Sender domain '{sender_domain}' contains "
                                               f"the brand '{brand}' but is not the real "
                                               "company domain."))
                    break

    # Reply-To pointing somewhere else
    reply_to = parseaddr(msg.get("Reply-To", ""))[1]
    if reply_to and "@" in reply_to:
        reply_dom = registered_domain(reply_to.split("@")[1])
        if sender_domain and reply_dom != sender_domain:
            findings.append(("medium", f"Reply-To address ({reply_dom}) differs from the "
                                       f"sender ({sender_domain})."))

    # Authentication results (if the mail server added them)
    auth = (msg.get("Authentication-Results", "") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if re.search(rf"{mech}=(fail|softfail|none)", auth):
            findings.append(("medium", f"{mech.upper()} check did not pass - sender may be spoofed."))

    return findings


# --------------------------------------------------------------------------
# Main analysis + report
# --------------------------------------------------------------------------

def analyse(msg):
    from_name, from_addr = parseaddr(msg.get("From", ""))
    sender_domain = registered_domain(from_addr.split("@")[1]) if "@" in from_addr else ""
    subject = str(msg.get("Subject", ""))
    body, links = extract_email_parts(msg)

    findings = []
    findings += [("Text", s, m) for s, m in check_text(subject, body)]
    findings += [("Link", s, m) for s, m in check_links(sender_domain, links)]
    findings += [("Sender", s, m) for s, m in check_sender(msg, sender_domain)]

    score = sum(WEIGHTS[s] for _, s, _ in findings)
    return {
        "from": f"{from_name} <{from_addr}>".strip(),
        "subject": subject,
        "findings": findings,
        "score": score,
    }


def risk_level(score: int) -> str:
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "NONE"


def print_report(result):
    level = risk_level(result["score"])
    print("=" * 64)
    print(f"From:    {result['from']}")
    print(f"Subject: {result['subject']}")
    print("-" * 64)

    if not result["findings"]:
        print("[OK] This email was checked and does not look like a likely "
              "phishing attack.")
        print("     If you still feel suspicious, be cautious anyway.")
    else:
        icons = {"high": "[!!!]", "medium": "[!!] ", "low": "[!]  "}
        for category, severity, message in result["findings"]:
            print(f"{icons[severity]} {category:<6} | {message}")
        print("-" * 64)
        print(f"WARNING: This email is possibly malicious (risk: {level}, "
              f"score {result['score']}).")
        print("         Do not click links or share details. If it claims to be from")
        print("         someone you know, confirm by phone or another channel first.")
    print("=" * 64 + "\n")


# --------------------------------------------------------------------------
# Demo emails
# --------------------------------------------------------------------------

DEMO_EMAILS = {
    "Obvious phishing": """\
From: "Microsoft Support" <security@rnicrosoft-support.com>
To: victim@example.ie
Reply-To: helpdesk@mail-verify.ru
Subject: URGENT: Your account will be suspended
Content-Type: text/plain

Hello User,

Your account will be suspended within 24 hours!! Please verify your account
immediately to avoid closure.

Click here to login: http://rnicrosoft-support.com.account-verify.ru/secure/login?session=8f3a9c2d11e4b7&redirect=confirm_identity_now

Regards,
Security Team
""",
    "Disguised link (HTML)": """\
From: "PayPal" <service@paypal.com>
To: victim@example.ie
Subject: Receipt for your payment
Content-Type: text/html

<html><body>
<p>Dear Customer,</p>
<p>We noticed a problem with a recent payment. Please
<a href="http://192.168.45.12/paypal/login">www.paypal.com/myaccount</a>
to update your billing details.</p>
</body></html>
""",
    "Legitimate email": """\
From: Jane Murphy <jane.murphy@seutcarlow.ie>
To: sarah@seutcarlow.ie
Subject: Notes from Tuesday's lecture
Content-Type: text/plain

Hi Sarah,

Here are the slides from Tuesday. You can also find them on the course page:
https://www.seutcarlow.ie/courses/se606/notes

Thanks,
Jane
""",
}


def run_demo():
    parser = Parser(policy=policy.default)
    for title, raw in DEMO_EMAILS.items():
        print(f"\n### Demo: {title}")
        print_report(analyse(parser.parsestr(raw)))


def main():
    ap = argparse.ArgumentParser(description="Detect common phishing clues in an email.")
    ap.add_argument("file", nargs="?", help="path to a .eml file")
    ap.add_argument("--demo", action="store_true", help="run built-in sample emails")
    args = ap.parse_args()

    if args.demo:
        run_demo()
    elif args.file:
        with open(args.file, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
        print_report(analyse(msg))
    else:
        ap.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()