import uuid
import hashlib
import json
import secrets


def generate_id() -> str:
    """
    Generate a random unique ID.
    Used for:
    - actionId
    - callId
    - approvalId
    - receiptId
    """
    return uuid.uuid4().hex


def generate_trace_id() -> str:
    """
    Generate a 16-byte (32 hex chars) trace ID.
    Must be non-zero lowercase hex.
    """
    while True:
        trace_id = secrets.token_hex(16)
        if int(trace_id, 16) != 0:
            return trace_id


def generate_span_id() -> str:
    """
    Generate an 8-byte (16 hex chars) span ID.
    Must be non-zero lowercase hex.
    """
    while True:
        span_id = secrets.token_hex(8)
        if int(span_id, 16) != 0:
            return span_id


def build_traceparent(trace_id=None, span_id=None):
    """
    Create a W3C traceparent header.
    Format:
    00-<traceid>-<spanid>-01
    """
    if trace_id is None:
        trace_id = generate_trace_id()

    if span_id is None:
        span_id = generate_span_id()

    return f"00-{trace_id}-{span_id}-01"


def canonical_json(obj):
    """
    Compact sorted JSON.
    Used before hashing.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":")
    )


def sha256_digest(obj):
    """
    SHA256 hash of compact sorted JSON.
    Used for approval argumentsDigest.
    """
    data = canonical_json(obj)

    return hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()


def content_hash(obj):
    """
    Used to detect replay conflicts.
    Same request => same hash
    Different request => different hash
    """
    return sha256_digest(obj)
