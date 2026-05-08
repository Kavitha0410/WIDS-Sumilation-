"""
Alert System Module
Formats and prints security alerts to the console, and triggers logging.
Each alert includes the attack type, severity, and optional details.
"""

from logging_system.logger import log_threat


class AlertSystem:
    """Handles generating and displaying security alerts."""

    SEVERITY_COLORS = {
        "High": "\033[91m",    # Red
        "Medium": "\033[93m",  # Yellow
        "Low": "\033[94m",     # Blue
        "RESET": "\033[0m",
    }

    def __init__(self, use_color: bool = True):
        self.use_color = use_color
        self.alert_count = 0

    def trigger_alert(self, attack_type: str, severity: str, details: str = ""):
        """
        Trigger an alert for a detected attack.

        Args:
            attack_type: Name of the detected attack type
            severity: 'High', 'Medium', or 'Low'
            details: Additional contextual information about the alert
        """
        self.alert_count += 1
        message = f"ALERT: {attack_type} ({severity} Severity)"
        if details:
            message += f" | {details}"

        if self.use_color:
            color = self.SEVERITY_COLORS.get(severity, "")
            reset = self.SEVERITY_COLORS["RESET"]
            print(f"{color}{message}{reset}")
        else:
            print(message)

        log_threat(attack_type, severity, details)

    def summary(self):
        """Print a summary of all alerts triggered this session."""
        print(f"\n[WIDS] Total alerts triggered this session: {self.alert_count}")
