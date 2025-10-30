#!/usr/bin/env python3
"""
KAVACH-V1 :: Access Control Module (compact)
Handles basic user authorization using role-based access control.
"""

import logging

class AccessControl:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Define simple role permissions
        self.permissions = {
            "admin": ["view_logs", "run_scan", "modify_config", "view_dashboard"],
            "analyst": ["view_logs", "view_dashboard"],
            "user": ["view_dashboard"]
        }

    def authorize(self, user, action):
        """Check if a user is authorized to perform a specific action"""
        role = getattr(user, "role", "user")  # Default to 'user' if not defined
        allowed = action in self.permissions.get(role, [])

        if allowed:
            self.logger.info(f"✅ Access granted: {user.name} ({role}) -> {action}")
        else:
            self.logger.warning(f"⛔ Access denied: {user.name} ({role}) -> {action}")

        return allowed


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    class DummyUser:
        def __init__(self, name, role):
            self.name = name
            self.role = role

    admin = DummyUser("Sonic", "admin")
    analyst = DummyUser("Echo", "analyst")
    user = DummyUser("Nova", "user")

    ac = AccessControl()
    ac.authorize(admin, "modify_config")
    ac.authorize(analyst, "run_scan")
    ac.authorize(user, "view_dashboard")
