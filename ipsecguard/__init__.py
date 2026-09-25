"""IPsecGuard AI — core analysis pipeline.

Two engines, kept strictly separate:
  * parser  -> OBSERVED fields (read from genuinely-plaintext IKE_SA_INIT)
  * ml       -> INFERRED fields (from encrypted-traffic metadata)

Every finding is tagged by how it was derived. The system never decrypts payloads.
"""
__version__ = "0.1.0"

from .errors import (
    ErrorCode,
    IPsecGuardError,
    PCAPValidationError,
    PCAPFileNotFoundError,
    EmptyPCAPError,
    CorruptedPCAPError,
    UnsupportedPCAPFormatError,
    InsufficientPacketsError,
    AnalysisPipelineError,
    FeatureExtractionError,
    InvalidInputParameterError,
    format_error_response,
)
from .pcap_validator import validate_pcap_file, check_pcap_magic_header
from .parser import parse_ike, dissect_ike_packet, validate_ike_parameters
from .validation import AttackValidationEngine, compare_sessions
from .findings import Finding, create_downgrade_finding, create_pfs_finding, OBSERVED, INFERRED, CONFIG
from .report import validation_report_md, executive_md, technical_md
from .benchmarking import SecurityBenchmarkEngine, run_security_evaluation
from .mode_detector import detect_ipsec_mode
from .analyze import analyze_pcap, safe_analyze_pcap
