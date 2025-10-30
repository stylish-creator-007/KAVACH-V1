import logging
import os
from datetime import datetime

def setup_logging():
    """Sets up both console and file logging for the KAVACH system."""
    log_dir = os.path.join(os.path.dirname(__file__), "logs")

    # Ensure logs directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "cybershield.log")

    # Log format
    log_format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.StreamHandler(),          # Console output
            logging.FileHandler(log_file)     # File output
        ]
    )

    logging.info("🛡️ Logging initialized — outputting to console and '%s'", log_file)
    return logging.getLogger("KAVACH")
