"""
TrustFeed — IOC and Retraction models
Schema matches technical diagram IOC Payload Schema exactly.
Pydantic handles validation. canonical_bytes() produces the
deterministic serialization that Ed25519 signs over.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


# ── IOC Model ─────────────────────────────────────────────────────────────────

class IOCModel(BaseModel):
    """
    Canonical IOC schema — matches technical diagram exactly.

    Field order here is the canonical order used for signing.
    Ed25519 signs over canonical_bytes() which serialises
    these fields in sorted-key JSON with no whitespace.
    """
    ioc_id:       str = Field(default_factory=lambda: str(uuid.uuid4()))
    type:         Literal["ipv4", "domain", "url", "hash", "email"]
    value:        str
    severity:     Literal["critical", "high", "medium", "low"]
    ttl_seconds:  int = Field(default=86400, gt=0)
    publisher_id: str
    nonce:        str   # base64(96-bit random) — set by publisher module
    timestamp:    str   # ISO-8601 UTC — set by publisher module
    signature:    Optional[str] = None   # base64(Ed25519) — set after signing
    stix_id:      Optional[str] = None   # set by export layer

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("IOC value cannot be empty")
        return v.strip()

    @field_validator("publisher_id")
    @classmethod
    def publisher_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("publisher_id cannot be empty")
        return v.strip()

    def canonical_bytes(self) -> bytes:
        """
        Produce deterministic bytes for signing.

        Algorithm:
          - Include all fields EXCEPT signature and stix_id
            (signature doesn't exist yet; stix_id is export-time)
          - Sort keys alphabetically
          - No whitespace
          - UTF-8 encoded

        Both publisher (signing) and verifier (verifying) call
        this method — they must produce identical bytes.
        """
        payload = {
            "ioc_id":       self.ioc_id,
            "nonce":        self.nonce,
            "publisher_id": self.publisher_id,
            "severity":     self.severity,
            "timestamp":    self.timestamp,
            "ttl_seconds":  self.ttl_seconds,
            "type":         self.type,
            "value":        self.value,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def is_expired(self) -> bool:
        """Check whether this IOC has passed its TTL."""
        issued_at = datetime.fromisoformat(self.timestamp)
        age_secs  = (datetime.now(timezone.utc) - issued_at).total_seconds()
        return age_secs > self.ttl_seconds

    def to_dict(self) -> dict:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "IOCModel":
        return cls(**data)


# ── Retraction Model ──────────────────────────────────────────────────────────

class RetractionModel(BaseModel):
    """
    Signed retraction record.

    Publishers use their Ed25519 private key to sign a retraction.
    Verifiers confirm the signature matches the original publisher
    before removing the IOC from the store.
    """
    retraction_id:  str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_id:         str   # UUID of the IOC being retracted
    publisher_id:   str   # must match original IOC publisher_id
    reason:         str   # human-readable reason
    timestamp:      str   # ISO-8601 UTC
    signature:      Optional[str] = None  # base64(Ed25519) over canonical_bytes()

    @field_validator("reason")
    @classmethod
    def reason_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Retraction reason cannot be empty")
        return v.strip()

    def canonical_bytes(self) -> bytes:
        """
        Deterministic bytes for retraction signing.
        Same pattern as IOCModel — sorted keys, no whitespace.
        """
        payload = {
            "ioc_id":        self.ioc_id,
            "publisher_id":  self.publisher_id,
            "reason":        self.reason,
            "retraction_id": self.retraction_id,
            "timestamp":     self.timestamp,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "RetractionModel":
        return cls(**data)


# ── Publisher Registry Model ──────────────────────────────────────────────────

class PublisherModel(BaseModel):
    """
    Publisher record stored in publisher registry.
    Holds the Ed25519 public key for IOC signature verification.
    """
    publisher_id:    str
    name:            str
    tier:            Literal[1, 2, 3]
    cert_path:       str   # path to ECDSA P-256 X.509 cert file
    ed25519_pub_key: str   # base64 encoded Ed25519 public key
    registered_at:   str   # ISO-8601 UTC
    is_active:       bool = True

    def to_dict(self) -> dict:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "PublisherModel":
        return cls(**data)