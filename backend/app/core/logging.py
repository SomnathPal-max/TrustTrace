import logging
import re
import sys

# Redaction patterns for log sanitization
REDACT_PATTERNS = [
    re.compile(r"0x[a-fA-F0-9]{64}"),  # Private keys
    re.compile(r"[a-zA-Z0-9_\-]{30,}"),  # Long API tokens
    re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),  # Aadhaar / Card numbers
    re.compile(r"\b\d{6}\b"),  # OTPs / PINs
]

class SanitizedFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in REDACT_PATTERNS:
            msg = pattern.sub("[REDACTED]", msg)
        return msg

def get_logger(name: str = "trusttrace") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            SanitizedFormatter(
                fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ"
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
    return logger

logger = get_logger("trusttrace")
