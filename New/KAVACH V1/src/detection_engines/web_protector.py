import re
import logging
from urllib.parse import urlparse, parse_qs

class WebAttackProtector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # SQL Injection patterns
        self.sql_injection_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
            r"insert(\s|\+)+into",
            r"drop(\s|\+)+table",
            r"update(\s|\+)+set",
            r"delete(\s|\+)+from"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"alert\s*\(",
            r"document\.cookie",
            r"<iframe.*?>",
            r"<img.*?onerror=.*?>"
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"etc/passwd",
            r"windows/win.ini",
            r"\.\.%2f",
            r"\.\.%5c"
        ]
    
    def detect_web_attacks(self, url=None, user_input=None, headers=None):
        """Detect various web application attacks"""
        detected_attacks = []
        
        if url:
            detected_attacks.extend(self.analyze_url(url))
        
        if user_input:
            detected_attacks.extend(self.analyze_user_input(user_input))
        
        if headers:
            detected_attacks.extend(self.analyze_headers(headers))
        
        return detected_attacks
    
    def analyze_url(self, url):
        """Analyze URL for attacks"""
        attacks = []
        
        try:
            parsed_url = urlparse(url)
            
            # Check for SQL injection in query parameters
            query_params = parse_qs(parsed_url.query)
            for param, values in query_params.items():
                for value in values:
                    if self.detect_sql_injection(value):
                        attacks.append({
                            'type': 'SQL_INJECTION',
                            'parameter': param,
                            'value': value,
                            'action': 'BLOCK_REQUEST'
                        })
                        self.logger.warning(f"SQL Injection detected in URL parameter: {param}")
                    
                    if self.detect_xss(value):
                        attacks.append({
                            'type': 'XSS',
                            'parameter': param,
                            'value': value,
                            'action': 'SANITIZE_INPUT'
                        })
                        self.logger.warning(f"XSS detected in URL parameter: {param}")
            
            # Check for path traversal in path
            if self.detect_path_traversal(parsed_url.path):
                attacks.append({
                    'type': 'PATH_TRAVERSAL',
                    'path': parsed_url.path,
                    'action': 'BLOCK_REQUEST'
                })
                self.logger.warning(f"Path traversal detected: {parsed_url.path}")
                
        except Exception as e:
            self.logger.error(f"URL analysis error: {e}")
        
        return attacks
    
    def analyze_user_input(self, user_input):
        """Analyze user input for attacks"""
        attacks = []
        
        if isinstance(user_input, str):
            if self.detect_sql_injection(user_input):
                attacks.append({
                    'type': 'SQL_INJECTION',
                    'input': user_input[:100],  # First 100 chars
                    'action': 'BLOCK_REQUEST'
                })
            
            if self.detect_xss(user_input):
                attacks.append({
                    'type': 'XSS',
                    'input': user_input[:100],
                    'action': 'SANITIZE_INPUT'
                })
            
            if self.detect_path_traversal(user_input):
                attacks.append({
                    'type': 'PATH_TRAVERSAL',
                    'input': user_input[:100],
                    'action': 'BLOCK_REQUEST'
                })
        
        return attacks
    
    def analyze_headers(self, headers):
        """Analyze HTTP headers for attacks"""
        attacks = []
        
        suspicious_headers = {
            'user-agent': self.analyze_user_agent,
            'referer': self.analyze_referer,
            'cookie': self.analyze_cookies
        }
        
        for header_name, header_value in headers.items():
            if header_name.lower() in suspicious_headers:
                analyzer = suspicious_headers[header_name.lower()]
                header_attacks = analyzer(header_value)
                attacks.extend(header_attacks)
        
        return attacks
    
    def detect_sql_injection(self, input_string):
        """Detect SQL injection attempts"""
        if not isinstance(input_string, str):
            return False
            
        input_lower = input_string.lower()
        
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_lower, re.IGNORECASE):
                return True
        
        return False
    
    def detect_xss(self, input_string):
        """Detect XSS attempts"""
        if not isinstance(input_string, str):
            return False
            
        for pattern in self.xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        
        return False
    
    def detect_path_traversal(self, input_string):
        """Detect path traversal attempts"""
        if not isinstance(input_string, str):
            return False
            
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        
        return False
    
    def analyze_user_agent(self, user_agent):
        """Analyze User-Agent header"""
        attacks = []
        
        if not user_agent:
            return attacks
        
        # Check for SQL injection in User-Agent
        if self.detect_sql_injection(user_agent):
            attacks.append({
                'type': 'SQL_INJECTION_USER_AGENT',
                'user_agent': user_agent[:100],
                'action': 'BLOCK_REQUEST'
            })
            self.logger.warning(f"SQL Injection in User-Agent: {user_agent[:100]}")
        
        return attacks
    
    def analyze_referer(self, referer):
        """Analyze Referer header"""
        attacks = []
        
        if not referer:
            return attacks
        
        # Check for malicious referer
        if self.detect_sql_injection(referer) or self.detect_xss(referer):
            attacks.append({
                'type': 'MALICIOUS_REFERER',
                'referer': referer[:100],
                'action': 'BLOCK_REQUEST'
            })
        
        return attacks
    
    def analyze_cookies(self, cookie_header):
        """Analyze Cookie header"""
        attacks = []
        
        if not cookie_header:
            return attacks
        
        # Check for SQL injection in cookies
        if self.detect_sql_injection(cookie_header):
            attacks.append({
                'type': 'SQL_INJECTION_COOKIE',
                'cookie': cookie_header[:100],
                'action': 'BLOCK_REQUEST'
            })
            self.logger.warning(f"SQL Injection in Cookie: {cookie_header[:100]}")
        
        return attacks
    
    def sanitize_input(self, user_input):
        """Sanitize user input to prevent attacks"""
        if not isinstance(user_input, str):
            return user_input
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', user_input)
        
        # Escape SQL special characters
        sanitized = sanitized.replace('\\', '\\\\')
        sanitized = sanitized.replace('%', '\\%')
        sanitized = sanitized.replace('_', '\\_')
        
        return sanitized