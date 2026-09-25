"""Comprehensive error handling & structured exception hierarchy for IPsecGuard AI.

Provides standard exception classes and structured error response formatters
covering all stages of the analysis pipeline:
- PCAP validation & file integrity
- Feature extraction & packet filtering
- IKE protocol dissection
- ML inference (classification & anomaly detection)
- NIST security scoring
- Report generation
"""
import datetime
from typing import Any, Dict, Optional


# ==============================================================================
# Error Codes Definition
# ==============================================================================

class ErrorCode:
    # PCAP Validation
    PCAP_FILE_NOT_FOUND = "PCAP_FILE_NOT_FOUND"
    PCAP_FILE_ACCESS_DENIED = "PCAP_FILE_ACCESS_DENIED"
    PCAP_EMPTY_FILE = "PCAP_EMPTY_FILE"
    PCAP_CORRUPTED = "PCAP_CORRUPTED"
    PCAP_UNSUPPORTED_FORMAT = "PCAP_UNSUPPORTED_FORMAT"
    PCAP_INSUFFICIENT_PACKETS = "PCAP_INSUFFICIENT_PACKETS"
    PCAP_NO_IPSEC_TRAFFIC = "PCAP_NO_IPSEC_TRAFFIC"

    # Pipeline Processing Stages
    PCAP_VALIDATION_FAILED = "PCAP_VALIDATION_FAILED"
    IKE_PARSING_FAILED = "IKE_PARSING_FAILED"
    FEATURE_EXTRACTION_FAILED = "FEATURE_EXTRACTION_FAILED"
    MODE_DETECTION_FAILED = "MODE_DETECTION_FAILED"
    CLASSIFICATION_FAILED = "CLASSIFICATION_FAILED"
    ANOMALY_DETECTION_FAILED = "ANOMALY_DETECTION_FAILED"
    SCORING_FAILED = "SCORING_FAILED"
    REPORT_GENERATION_FAILED = "REPORT_GENERATION_FAILED"
    INTERNAL_ANALYSIS_ERROR = "INTERNAL_ANALYSIS_ERROR"

    # Input / Simulation Validation
    INVALID_INPUT_PARAMETER = "INVALID_INPUT_PARAMETER"


# ==============================================================================
# Exception Hierarchy
# ==============================================================================

class IPsecGuardError(Exception):
    """Base exception for all IPsecGuard AI operational and validation errors."""
    def __init__(
        self,
        message: str,
        error_code: str = ErrorCode.INTERNAL_ANALYSIS_ERROR,
        stage: str = "general",
        retryable: bool = False,
        details: Optional[Any] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.stage = stage
        self.retryable = retryable
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return format_error_response(
            message=self.message,
            error_code=self.error_code,
            stage=self.stage,
            retryable=self.retryable,
            details=self.details
        )


class PCAPValidationError(IPsecGuardError):
    """Raised when an uploaded/provided PCAP file fails format or integrity validation."""
    def __init__(
        self,
        message: str,
        error_code: str = ErrorCode.PCAP_VALIDATION_FAILED,
        retryable: bool = False,
        details: Optional[Any] = None
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            stage="pcap_validation",
            retryable=retryable,
            details=details
        )


class PCAPFileNotFoundError(PCAPValidationError):
    def __init__(self, path: str):
        super().__init__(
            message=f"The specified PCAP capture file was not found: '{path}'.",
            error_code=ErrorCode.PCAP_FILE_NOT_FOUND,
            retryable=False,
            details={"path": path}
        )


class EmptyPCAPError(PCAPValidationError):
    def __init__(self, path: str):
        super().__init__(
            message="The provided PCAP capture file is empty (0 bytes).",
            error_code=ErrorCode.PCAP_EMPTY_FILE,
            retryable=False,
            details={"path": path, "file_size": 0}
        )


class CorruptedPCAPError(PCAPValidationError):
    def __init__(self, path: str, reason: str = "Invalid file structure or truncated packet data"):
        super().__init__(
            message=f"The capture file is corrupted and cannot be parsed: {reason}.",
            error_code=ErrorCode.PCAP_CORRUPTED,
            retryable=False,
            details={"path": path, "reason": reason}
        )


class UnsupportedPCAPFormatError(PCAPValidationError):
    def __init__(self, path: str, detected_header: Optional[str] = None):
        super().__init__(
            message="Unsupported capture file format. Expected a standard PCAP (libpcap) or PCAPNG file.",
            error_code=ErrorCode.PCAP_UNSUPPORTED_FORMAT,
            retryable=False,
            details={"path": path, "detected_header": detected_header}
        )


class InsufficientPacketsError(PCAPValidationError):
    def __init__(self, path: str, packet_count: int, min_required: int = 1, traffic_type: str = "packets"):
        super().__init__(
            message=f"Insufficient {traffic_type} in capture ({packet_count} found, minimum {min_required} required).",
            error_code=ErrorCode.PCAP_INSUFFICIENT_PACKETS,
            retryable=True,
            details={"path": path, "packet_count": packet_count, "min_required": min_required}
        )


class AnalysisPipelineError(IPsecGuardError):
    """Raised when an internal processing stage fails during analysis."""
    def __init__(
        self,
        message: str,
        stage: str,
        error_code: str = ErrorCode.INTERNAL_ANALYSIS_ERROR,
        retryable: bool = False,
        details: Optional[Any] = None
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            stage=stage,
            retryable=retryable,
            details=details
        )


class FeatureExtractionError(AnalysisPipelineError):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            stage="feature_extraction",
            error_code=ErrorCode.FEATURE_EXTRACTION_FAILED,
            retryable=True,
            details=details
        )


class InvalidInputParameterError(IPsecGuardError):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            error_code=ErrorCode.INVALID_INPUT_PARAMETER,
            stage="input_validation",
            retryable=True,
            details=details
        )


# ==============================================================================
# Helper Function for Consistent Structured Error Responses
# ==============================================================================

def format_error_response(
    message: str,
    error_code: str = ErrorCode.INTERNAL_ANALYSIS_ERROR,
    stage: str = "general",
    retryable: bool = False,
    details: Optional[Any] = None
) -> Dict[str, Any]:
    """Generates a uniform, sanitized error dictionary across API and CLI layers."""
    sanitized_details = details
    if isinstance(details, Exception):
        sanitized_details = str(details)

    return {
        "status": "error",
        "error_code": error_code,
        "message": message,
        "stage": stage,
        "retryable": retryable,
        "details": sanitized_details if sanitized_details is not None else {},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
