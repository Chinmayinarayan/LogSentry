"""
Common Data Models for LogSentry.

Provides standardized dataclasses across E1 WATCH, E2 PARSE, E3 VAULT, and E4 SIGNAL:
- LogEvent: Valid parsed & classified operational log event.
- AlertRecord: Sliding-window anomaly burst alert.
- QuarantineRecord: Corrupted, malformed, or unauthorized input quarantined as evidence.
- UserSession: Authenticated user identity and RBAC role.

All models provide .to_dict(), .from_dict(), and .from_row() adapters to maintain 100%
backward compatibility with existing dictionary-based internal interfaces.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, Union
import sqlite3


@dataclass
class LogEvent:
    """
    Represents a successfully parsed, classified operational log event (HDFS or NASA-HTTP).
    Stored in the 'events' table.
    """
    source: str
    log_level: str
    raw_message: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    component_host: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to dictionary matching existing API & parser contracts."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "log_level": self.log_level,
            "component_host": self.component_host,
            "raw_message": self.raw_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEvent":
        """Construct LogEvent from dictionary."""
        return cls(
            id=data.get("id"),
            timestamp=data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source=data.get("source", "UNKNOWN"),
            log_level=data.get("log_level", "INFO"),
            component_host=data.get("component_host"),
            raw_message=data.get("raw_message") or data.get("message", ""),
        )

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, tuple, dict]) -> "LogEvent":
        """Construct LogEvent from sqlite3.Row or dict."""
        if isinstance(row, dict):
            return cls.from_dict(row)
        keys = row.keys() if hasattr(row, "keys") else []
        return cls(
            id=row["id"] if "id" in keys else None,
            timestamp=row["timestamp"],
            source=row["source"],
            log_level=row["log_level"],
            component_host=row["component_host"] if "component_host" in keys else None,
            raw_message=row["raw_message"],
        )


@dataclass
class AlertRecord:
    """
    Represents an anomaly burst alert raised by E2 sliding-window detection.
    Stored in the 'alerts' table.
    """
    source: str
    alert_type: str
    event_count: int
    window_duration_sec: int
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    status: str = "ACTIVE"
    alert_id: Optional[int] = None
    updated_at: Optional[str] = None
    updated_by: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to dictionary matching existing alert API contracts."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "alert_type": self.alert_type,
            "event_count": self.event_count,
            "window_duration_sec": self.window_duration_sec,
            "status": self.status,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertRecord":
        """Construct AlertRecord from dictionary."""
        return cls(
            alert_id=data.get("alert_id") or data.get("id"),
            timestamp=data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source=data.get("source", "UNKNOWN"),
            alert_type=data.get("alert_type") or data.get("type", "ANOMALY_BURST"),
            event_count=int(data.get("event_count") or data.get("count", 0)),
            window_duration_sec=int(data.get("window_duration_sec") or data.get("window", 60)),
            status=data.get("status", "ACTIVE"),
            updated_at=data.get("updated_at"),
            updated_by=data.get("updated_by"),
        )

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, tuple, dict]) -> "AlertRecord":
        """Construct AlertRecord from sqlite3.Row or dict."""
        if isinstance(row, dict):
            return cls.from_dict(row)
        keys = row.keys()
        return cls(
            alert_id=row["alert_id"] if "alert_id" in keys else (row["id"] if "id" in keys else None),
            timestamp=row["timestamp"],
            source=row["source"],
            alert_type=row["alert_type"],
            event_count=row["event_count"],
            window_duration_sec=row["window_duration_sec"],
            status=row["status"] if "status" in keys else "ACTIVE",
            updated_at=row["updated_at"] if "updated_at" in keys else None,
            updated_by=row["updated_by"] if "updated_by" in keys else None,
        )


@dataclass
class QuarantineRecord:
    """
    Represents an invalid, malformed, binary, or wrong-source record quarantined as evidence.
    Stored in the 'rejected_lines' table.
    """
    source: str
    reason: str
    raw_bytes: bytes
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    rejected_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataclass to dictionary matching existing rejected_lines API contracts."""
        return {
            "rejected_id": self.rejected_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "reason": self.reason,
            "raw_bytes": self.raw_bytes,
            "raw_text_preview": self.raw_bytes.decode("utf-8", errors="replace")[:200] if isinstance(self.raw_bytes, bytes) else str(self.raw_bytes)[:200],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QuarantineRecord":
        """Construct QuarantineRecord from dictionary."""
        raw = data.get("raw_bytes", b"")
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        return cls(
            rejected_id=data.get("rejected_id") or data.get("id"),
            timestamp=data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source=data.get("source", "UNKNOWN"),
            reason=data.get("reason", "Format violation"),
            raw_bytes=raw,
        )

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, tuple, dict]) -> "QuarantineRecord":
        """Construct QuarantineRecord from sqlite3.Row or dict."""
        if isinstance(row, dict):
            return cls.from_dict(row)
        keys = row.keys()
        raw = row["raw_bytes"]
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        return cls(
            rejected_id=row["rejected_id"] if "rejected_id" in keys else None,
            timestamp=row["timestamp"],
            source=row["source"],
            reason=row["reason"],
            raw_bytes=raw,
        )


@dataclass
class UserSession:
    """
    Represents an authenticated user identity and RBAC role.
    Used for server-side authorization in E4 SIGNAL.
    """
    user_id: int
    username: str
    role: str
    created_at: Optional[str] = None

    @property
    def is_admin(self) -> bool:
        return self.role.upper() == "ADMIN"

    @property
    def is_operator(self) -> bool:
        return self.role.upper() in ("ADMIN", "OPERATOR")

    @property
    def is_viewer(self) -> bool:
        return self.role.upper() in ("ADMIN", "OPERATOR", "VIEWER")

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary matching /api/me response."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserSession":
        """Construct UserSession from dictionary."""
        return cls(
            user_id=int(data.get("user_id") or data.get("id", 0)),
            username=data.get("username", "guest"),
            role=data.get("role", "VIEWER").upper(),
            created_at=data.get("created_at") or data.get("updated_at"),
        )

    @classmethod
    def from_row(cls, row: Union[sqlite3.Row, tuple, dict]) -> "UserSession":
        """Construct UserSession from sqlite3.Row or dict."""
        if isinstance(row, dict):
            return cls.from_dict(row)
        keys = row.keys()
        return cls(
            user_id=row["user_id"],
            username=row["username"],
            role=row["role"],
            created_at=row["updated_at"] if "updated_at" in keys else None,
        )
