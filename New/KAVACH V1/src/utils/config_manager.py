import json
import os
from typing import Dict, Any

class ConfigManager:
    def __init__(self, config_file='config/cybershield_config.json'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "security": {
                "threat_level_threshold": 80,
                "auto_block_malicious_ips": True,
                "emergency_shutdown_enabled": True,
                "shutdown_threshold": 20
            },
            "monitoring": {
                "file_system_monitoring": True,
                "network_monitoring": True,
                "process_monitoring": True,
                "behavior_analysis": True
            },
            "logging": {
                "level": "INFO",
                "max_file_size_mb": 100,
                "backup_count": 5
            },
            "prevention": {
                "auto_quarantine": True,
                "block_suspicious_ports": True,
                "terminate_malicious_processes": True
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with default config
                    return self.merge_configs(default_config, loaded_config)
            else:
                # Create config directory and file
                os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
                
        except Exception as e:
            print(f"Error loading config: {e}")
            return default_config
    
    def merge_configs(self, default: Dict, custom: Dict) -> Dict:
        """Merge default and custom configurations"""
        merged = default.copy()
        
        for key, value in custom.items():
            if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
                merged[key] = self.merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config_ref = self.config
        
        for k in keys[:-1]:
            if k not in config_ref or not isinstance(config_ref[k], dict):
                config_ref[k] = {}
            config_ref = config_ref[k]
        
        config_ref[keys[-1]] = value
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def reload_config(self):
        """Reload configuration from file"""
        self.config = self.load_config()