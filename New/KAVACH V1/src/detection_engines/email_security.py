import re
import logging
from urllib.parse import urlparse
import dns.resolver
import smtplib
import os
import time
from datetime import datetime


class PhishingDetector:
    """Detects potential phishing or scam indicators in emails."""
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_keywords = [
            'verify your account', 'password reset', 'urgent action required',
            'suspended account', 'security alert', 'click here', 'login now',
            'banking update', 'paypal', 'irs', 'tax refund', 'lottery winner',
            'confirm your details', 'account verification', 'unlock account'
        ]
        self.suspicious_domains = set()
        self.load_phishing_domains()

    def load_phishing_domains(self):
        """Load known phishing domains from data file."""
        try:
            path = "data/phishing_domains.txt"
            if not os.path.exists(path):
                self.logger.warning("Phishing domain list not found, continuing without it.")
                return
            with open(path, 'r') as f:
                self.suspicious_domains = set(
                    line.strip().lower() for line in f if line.strip()
                )
            self.logger.info(f"Loaded {len(self.suspicious_domains)} phishing domains.")
        except Exception as e:
            self.logger.error(f"Error loading phishing domains: {e}")

    # ----------------------------
    # Email Analysis Core
    # ----------------------------
    def analyze_email(self, email_content: str, sender: str, subject: str):
        """Comprehensive phishing detection pipeline."""
        threats = []

        # Analyze sender
        threats.extend(self.analyze_sender(sender))

        # Analyze subject
        threats.extend(self.analyze_subject(subject))

        # Analyze body/content
        threats.extend(self.analyze_content(email_content))

        # Analyze embedded URLs
        urls = self.extract_urls(email_content)
        for url in urls:
            threats.extend(self.analyze_url(url))

        if not threats:
            threats.append("No phishing indicators detected.")

        return {
            "sender": sender,
            "subject": subject,
            "urls": urls,
            "threats": threats,
        }

    # ----------------------------
    # Sender Analysis
    # ----------------------------
    def analyze_sender(self, sender):
        threats = []
        try:
            domain = sender.split('@')[-1].lower()
            if domain in self.suspicious_domains:
                threats.append(f"Sender domain {domain} is known phishing domain.")
            elif not self.validate_mx_record(domain):
                threats.append(f"Sender domain {domain} has invalid or missing MX record.")
        except Exception as e:
            threats.append(f"Error analyzing sender: {e}")
        return threats

    def validate_mx_record(self, domain):
        """Check if domain has valid mail exchange records."""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            return len(answers) > 0
        except Exception:
            return False

    # ----------------------------
    # Subject and Content Analysis
    # ----------------------------
    def analyze_subject(self, subject):
        threats = []
        subject_lower = subject.lower()
        for keyword in self.suspicious_keywords:
            if keyword in subject_lower:
                threats.append(f"Suspicious keyword in subject: '{keyword}'")
        return threats

    def analyze_content(self, content):
        threats = []
        text = content.lower()
        for keyword in self.suspicious_keywords:
            if keyword in text:
                threats.append(f"Suspicious phrase in email body: '{keyword}'")
        return threats

    # ----------------------------
    # URL Extraction & Analysis
    # ----------------------------
    def extract_urls(self, content):
        """Find all URLs in the email content."""
        url_pattern = re.compile(r'https?://[^\s\'">]+')
        return url_pattern.findall(content)

    def analyze_url(self, url):
        threats = []
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Suspicious domain
        if domain in self.suspicious_domains:
            threats.append(f"Phishing domain detected in URL: {domain}")

        # Mismatched domain pattern (e.g., fake bank login)
        fake_patterns = ['paypal-', 'bank-', 'secure-', 'update-', 'login-', 'verify-']
        for pattern in fake_patterns:
            if pattern in domain:
                threats.append(f"Suspicious domain pattern: {domain}")

        # Shortened URLs
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
        if any(s in domain for s in shorteners):
            threats.append(f"Shortened URL detected: {domain}")

        return threats


# ----------------------------
# Standalone Test Runner
# ----------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S"
    )

    detector = PhishingDetector()

    test_emails = [
        {
            "sender": "security@paypal-alerts.com",
            "subject": "Urgent Action Required - Verify Your Account",
            "content": """
                Dear user,
                Your PayPal account is temporarily suspended. Please verify your account immediately.
                Click here: https://paypal-login-secure-update.com/verify
            """
        },
        {
            "sender": "news@trustedsource.com",
            "subject": "Your weekly newsletter",
            "content": "Here is your update from our trusted service. Thank you!"
        },
        {
            "sender": "info@tinyurl.com",
            "subject": "Check this out!",
            "content": "Hey! Visit this link for rewards: https://bit.ly/free-money"
        }
    ]

    print("\n✉️  Starting Email Security Analysis Monitor...\n")

    try:
        while True:
            os.system("clear")
            print("📧 KAVACH-V1 :: Email Security Monitor\n" + "-" * 60)
            print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

            for idx, email in enumerate(test_emails, 1):
                result = detector.analyze_email(email['content'], email['sender'], email['subject'])
                print(f"Email #{idx}: From {result['sender']} | Subject: {result['subject']}")
                print(f"URLs Found: {', '.join(result['urls']) if result['urls'] else 'None'}")

                print("\nThreat Analysis:")
                for threat in result['threats']:
                    print(f"  ⚠️  {threat}")
                print("-" * 60)

            print("\nRefreshing in 10 seconds... (Press Ctrl+C to exit)")
            time.sleep(10)

    except KeyboardInterrupt:
        print("\n🛑 Email Security Monitor stopped by user.")
