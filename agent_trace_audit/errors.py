class TraceAuditError(Exception):
    """Base error for trace collection and reports."""


class InputFormatError(TraceAuditError):
    """An input file cannot be read or parsed."""
