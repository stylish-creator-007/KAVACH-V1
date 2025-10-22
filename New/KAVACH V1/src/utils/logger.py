import logging
import sys
from datetime import datetime
import os

def setup_logging(log_level=logging.INFO, log_file='cybershield.log'):
    """Setup comprehensive logging configuration"""
    
    # Create logs directory if it doesn't exist
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, log_file)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Special handler for security events
    security_handler = logging.FileHandler(os.path.join(log_dir, 'security_events.log'))
    security_handler.setLevel(logging.WARNING)
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
    )
    security_handler.setFormatter(security_formatter)
    root_logger.addHandler(security_handler)
    
    return root_logger

class SecurityLogger:
    """Specialized logger for security events"""
    
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_threat(self, threat_type, details):
        """Log security threats"""
        self.logger.warning(f"THREAT_DETECTED - {threat_type}: {details}")
    
    def log_incident(self, incident_type, severity, details):
        """Log security incidents"""
        if severity == 'HIGH':
            self.logger.error(f"INCIDENT - {incident_type} - {severity}: {details}")
        else:
            self.logger.warning(f"INCIDENT - {incident_type} - {severity}: {details}")
    
    def log_prevention(self, action, target, result):
        """Log prevention actions"""
        self.logger.info(f"PREVENTION - {action} on {target}: {result}")