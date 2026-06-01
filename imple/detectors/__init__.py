from .base import BaseDetector, PassiveDetector
from .sqli import SQLiDetector
from .xss import XSSDetector
from .ssrf import SSRFDetector
from .idor import IDORDetector
from .path_traversal import PathTraversalDetector
from .xxe import XXEDetector
from .file_upload import FileUploadDetector
from .crypto import CryptographicFailuresDetector
from .security_misconfig import SecurityMisconfigDetector
from .components import VulnerableComponentsDetector
from .auth import AuthFailuresDetector
from .integrity import IntegrityDetector

ALL_DETECTORS = {
    # A01 - Broken Access Control
    "idor": IDORDetector,
    "path_traversal": PathTraversalDetector,
    # A02 - Cryptographic Failures
    "crypto": CryptographicFailuresDetector,
    # A03 - Injection
    "sqli": SQLiDetector,
    "xss": XSSDetector,
    # A04 - Insecure Design
    "file_upload": FileUploadDetector,
    # A05 - Security Misconfiguration
    "security_misconfig": SecurityMisconfigDetector,
    "xxe": XXEDetector,
    # A06 - Vulnerable Components
    "components": VulnerableComponentsDetector,
    # A07 - Auth Failures
    "auth": AuthFailuresDetector,
    # A08 - Software & Data Integrity
    "integrity": IntegrityDetector,
    # A10 - SSRF
    "ssrf": SSRFDetector,
}

__all__ = [
    "BaseDetector", "PassiveDetector",
    "SQLiDetector", "XSSDetector", "SSRFDetector", "IDORDetector",
    "PathTraversalDetector", "XXEDetector", "FileUploadDetector",
    "CryptographicFailuresDetector", "SecurityMisconfigDetector",
    "VulnerableComponentsDetector", "AuthFailuresDetector",
    "IntegrityDetector",
    "ALL_DETECTORS",
]
