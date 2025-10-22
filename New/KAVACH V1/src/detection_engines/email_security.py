import re
import logging
from urllib.parse import urlparse
import dns.resolver
import smtplib

class PhishingDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_keywords = [
            'verify your account', 'password reset', 'urgent action required',
            'suspended account', 'security alert', 'click here', 'login now',
            'banking update', 'paypal', 'irs', 'tax refund', 'lottery winner'
        ]
        self.suspicious_domains = set()
        self.load_phishing_domains()
    
    def load_phishing_domains(self):
        """Load known phishing domains"""
        try:
            with open('data/phishing_domains.txt', 'r') as f:
                self.suspicious_domains = set(line.strip().lower() for line in f if line.strip())
        except Exception as e:
            self.logger.error(f"Error loading phishing domains: {e}")
    
    def analyze_email(self, email_content, sender, subject):
        """Comprehensive email analysis for phishing"""
        threats = []
        
        # Analyze sender
        sender_threats = self.analyze_sender(sender)
        threats.extend(sender_threats)
        
        # Analyze subject
        subject_threats = self.analyze_subject(subject)
        threats.extend(subject_threats)
        
        # Analyze content
        content_threats = self.analyze_content(email_content)
        threats.extend(content_threats)
        
        # Analyze URLs in email
        url_threats = self.analyze_urls_in_content(email_content)
        threats.extend(url_threats)
        
        # Calculate overall phishing score
        phishing_score = self.calculate_phishing_score(threats)
        
        return {
            'is_phishing': phishing_score > 0.7,
            'phishing_score': phishing_score,
            'threats': threats,
            'recommendation': 'BLOCK' if phishing_score > 0.7 else 'CAUTION' if phishing_score > 0.4 else 'SAFE'
        }
    
    def analyze_sender(self, sender):
        """Analyze email sender"""
        threats = []
        
        if not sender:
            return threats
        
        # Check for spoofed email addresses
        if self.detect_email_spoofing(sender):
            threats.append({
                'type': 'EMAIL_SPOOFING',
                'sender': sender,
                'confidence': 'HIGH'
            })
            self.logger.warning(f"Possible email spoofing: {sender}")
        
        # Check domain reputation
        domain = self.extract_domain(sender)
        if domain and domain.lower() in self.suspicious_domains:
            threats.append({
                'type': 'KNOWN_PHISHING_DOMAIN',
                'domain': domain,
                'confidence': 'HIGH'
            })
        
        return threats
    
    def analyze_subject(self, subject):
        """Analyze email subject"""
        threats = []
        
        if not subject:
            return threats
        
        subject_lower = subject.lower()
        
        # Check for urgency keywords
        urgency_keywords = ['urgent', 'immediate', 'important', 'action required', 'attention']
        if any(keyword in subject_lower for keyword in urgency_keywords):
            threats.append({
                'type': 'URGENCY_TACTIC',
                'subject': subject,
                'confidence': 'MEDIUM'
            })
        
        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword in subject_lower:
                threats.append({
                    'type': 'SUSPICIOUS_SUBJECT',
                    'keyword': keyword,
                    'confidence': 'MEDIUM'
                })
        
        return threats
    
    def analyze_content(self, content):
        """Analyze email content"""
        threats = []
        
        if not content:
            return threats
        
        content_lower = content.lower()
        
        # Check for suspicious phrases
        for keyword in self.suspicious_keywords:
            if keyword in content_lower:
                threats.append({
                    'type': 'SUSPICIOUS_CONTENT',
                    'keyword': keyword,
                    'confidence': 'MEDIUM'
                })
        
        # Check for grammar and spelling issues (simplified)
        if self.detect_poor_grammar(content):
            threats.append({
                'type': 'POOR_GRAMMAR',
                'confidence': 'LOW'
            })
        
        return threats
    
    def analyze_urls_in_content(self, content):
        """Analyze URLs in email content"""
        threats = []
        
        if not content:
            return threats
        
        # Extract URLs using simple regex
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            url_threats = self.analyze_single_url(url)
            threats.extend(url_threats)
        
        return threats
    
    def analyze_single_url(self, url):
        """Analyze a single URL for phishing indicators"""
        threats = []
        
        try:
            parsed_url = urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed_url.netloc.lower()
            
            # Check against known phishing domains
            if domain in self.suspicious_domains:
                threats.append({
                    'type': 'KNOWN_PHISHING_URL',
                    'url': url,
                    'domain': domain,
                    'confidence': 'HIGH'
                })
                self.logger.warning(f"Known phishing URL: {url}")
            
            # Check for URL shortening services
            if self.is_url_shortener(domain):
                threats.append({
                    'type': 'URL_SHORTENER',
                    'url': url,
                    'confidence': 'MEDIUM'
                })
            
            # Check for IP address in URL
            if self.is_ip_address(domain):
                threats.append({
                    'type': 'IP_URL',
                    'url': url,
                    'confidence': 'HIGH'
                })
            
            # Check for suspicious characters in domain
            if self.has_suspicious_characters(domain):
                threats.append({
                    'type': 'SUSPICIOUS_DOMAIN',
                    'domain': domain,
                    'confidence': 'MEDIUM'
                })
                
        except Exception as e:
            self.logger.error(f"URL analysis error: {e}")
        
        return threats
    
    def detect_email_spoofing(self, email):
        """Detect potential email spoofing"""
        try:
            # Simple spoofing detection based on domain inconsistencies
            domain = self.extract_domain(email)
            if not domain:
                return False
            
            # Check if domain has valid MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                if not mx_records:
                    return True
            except:
                return True  # No MX records could indicate spoofing
            
            return False
        except:
            return False
    
    def extract_domain(self, email):
        """Extract domain from email address"""
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email)
        return match.group(1) if match else None
    
    def detect_poor_grammar(self, text):
        """Simple poor grammar detection"""
        # This is a simplified version - real implementation would be more sophisticated
        common_errors = [
            r'\bi\s+is\b', r'\byou\s+is\b', r'\bwe\s+is\b',  # Basic grammar errors
            r'\burgent\s+!!+',  # Multiple exclamation marks
            r'\b[A-Z]+\s+[A-Z]+\b'  # ALL CAPS words
        ]
        
        for pattern in common_errors:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def is_url_shortener(self, domain):
        """Check if domain is a URL shortener"""
        shorteners = {'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd'}
        return domain in shorteners
    
    def is_ip_address(self, domain):
        """Check if domain is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return re.match(ip_pattern, domain) is not None
    
    def has_suspicious_characters(self, domain):
        """Check for suspicious characters in domain"""
        # Look for domains with multiple hyphens or unusual characters
        if domain.count('-') > 3:
            return True
        
        # Look for numbers in domain (can be suspicious)
        if re.search(r'\d{4,}', domain):
            return True
        
        return False
    
    def calculate_phishing_score(self, threats):
        """Calculate overall phishing probability score"""
        if not threats:
            return 0.0
        
        score = 0.0
        high_count = sum(1 for t in threats if t.get('confidence') == 'HIGH')
        medium_count = sum(1 for t in threats if t.get('confidence') == 'MEDIUM')
        low_count = sum(1 for t in threats if t.get('confidence') == 'LOW')
        
        score = (high_count * 0.5 + medium_count * 0.3 + low_count * 0.1) / len(threats)
        return min(1.0, score)
    
    def monitor_emails(self):
        """Monitor for phishing emails (placeholder for email integration)"""
        # This would integrate with email clients or servers
        # For now, return empty list
        return []