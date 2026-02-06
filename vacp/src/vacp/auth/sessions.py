"""
Session Management for Koba/VACP

Provides:
- Session creation and validation
- Session refresh and expiration
- Session activity tracking
- Concurrent session limits
"""

# DEPRECATED: This session module uses in-memory storage and is not used by the main API server.
# The canonical auth system is vacp.core.auth which manages sessions via UserDatabase.
# This module is retained for reference but should not be imported for new code.

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
import threading


class SessionStatus(str, Enum):
    """Status of a session."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"


@dataclass
class Session:
    """Represents an authenticated session."""
    id: str
    subject_id: str
    subject_type: str  # "user", "service", "api_key"
    tenant_id: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    refresh_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        if self.status != SessionStatus.ACTIVE:
            return False
        return datetime.now(timezone.utc) < self.expires_at

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(timezone.utc) >= self.expires_at

    def time_remaining(self) -> timedelta:
        """Get time remaining until expiration."""
        remaining = self.expires_at - datetime.now(timezone.utc)
        return max(remaining, timedelta(0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_activity_at": self.last_activity_at.isoformat(),
            "status": self.status.value,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
        }


class SessionManager:
    """
    Manages authenticated sessions.

    Features:
    - Session creation with configurable expiration
    - Session refresh/extension
    - Activity tracking
    - Concurrent session limits
    - Session revocation
    """

    DEFAULT_SESSION_DURATION = timedelta(days=30)
    DEFAULT_REFRESH_DURATION = timedelta(days=30)
    DEFAULT_INACTIVITY_TIMEOUT = timedelta(days=30)

    def __init__(
        self,
        session_duration: Optional[timedelta] = None,
        refresh_duration: Optional[timedelta] = None,
        inactivity_timeout: Optional[timedelta] = None,
        max_concurrent_sessions: int = 5,
    ):
        self.session_duration = session_duration or self.DEFAULT_SESSION_DURATION
        self.refresh_duration = refresh_duration or self.DEFAULT_REFRESH_DURATION
        self.inactivity_timeout = inactivity_timeout or self.DEFAULT_INACTIVITY_TIMEOUT
        self.max_concurrent_sessions = max_concurrent_sessions

        self._sessions: Dict[str, Session] = {}  # session_id -> Session
        self._subject_sessions: Dict[str, List[str]] = {}  # subject_id -> [session_ids]
        self._refresh_tokens: Dict[str, str] = {}  # refresh_token -> session_id
        self._lock = threading.Lock()

    def create_session(
        self,
        subject_id: str,
        subject_type: str,
        tenant_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Session:
        """
        Create a new session.

        May revoke oldest sessions if concurrent limit is exceeded.
        """
        session_id = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(48)
        now = datetime.now(timezone.utc)

        session = Session(
            id=session_id,
            subject_id=subject_id,
            subject_type=subject_type,
            tenant_id=tenant_id,
            created_at=now,
            expires_at=now + self.session_duration,
            last_activity_at=now,
            status=SessionStatus.ACTIVE,
            ip_address=ip_address,
            user_agent=user_agent,
            refresh_token=refresh_token,
            metadata=metadata or {},
        )

        with self._lock:
            # Check and enforce concurrent session limit
            if subject_id in self._subject_sessions:
                active_sessions = [
                    sid for sid in self._subject_sessions[subject_id]
                    if sid in self._sessions and self._sessions[sid].is_valid()
                ]

                # Revoke oldest if at limit
                while len(active_sessions) >= self.max_concurrent_sessions:
                    oldest_id = active_sessions.pop(0)
                    if oldest_id in self._sessions:
                        self._sessions[oldest_id].status = SessionStatus.REVOKED

                self._subject_sessions[subject_id] = active_sessions
            else:
                self._subject_sessions[subject_id] = []

            self._sessions[session_id] = session
            self._subject_sessions[subject_id].append(session_id)
            self._refresh_tokens[refresh_token] = session_id

        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session.is_valid():
                return session
            return None

    def validate_session(self, session_id: str) -> tuple[bool, Optional[Session], Optional[str]]:
        """
        Validate a session.

        Returns (is_valid, session, error_message).
        Also updates last activity time if valid.
        """
        with self._lock:
            session = self._sessions.get(session_id)

        if session is None:
            return False, None, "Session not found"

        if session.status == SessionStatus.REVOKED:
            return False, session, "Session has been revoked"

        if session.status == SessionStatus.LOCKED:
            return False, session, "Session is locked"

        if session.is_expired():
            with self._lock:
                session.status = SessionStatus.EXPIRED
            return False, session, "Session has expired"

        # Check inactivity timeout
        now = datetime.now(timezone.utc)
        if now - session.last_activity_at > self.inactivity_timeout:
            with self._lock:
                session.status = SessionStatus.EXPIRED
            return False, session, "Session timed out due to inactivity"

        # Update activity
        with self._lock:
            session.last_activity_at = now

        return True, session, None

    def refresh_session(self, refresh_token: str) -> Optional[Session]:
        """
        Refresh a session using its refresh token.

        Returns a new session if successful.
        """
        with self._lock:
            session_id = self._refresh_tokens.get(refresh_token)
            if session_id is None:
                return None

            old_session = self._sessions.get(session_id)
            if old_session is None:
                return None

            # Check if refresh is still valid
            now = datetime.now(timezone.utc)
            refresh_expires = old_session.created_at + self.refresh_duration
            if now > refresh_expires:
                return None

            # Revoke old session
            old_session.status = SessionStatus.REVOKED
            del self._refresh_tokens[refresh_token]

        # Create new session
        return self.create_session(
            subject_id=old_session.subject_id,
            subject_type=old_session.subject_type,
            tenant_id=old_session.tenant_id,
            ip_address=old_session.ip_address,
            user_agent=old_session.user_agent,
            metadata=old_session.metadata,
        )

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False

            session.status = SessionStatus.REVOKED

            # Also revoke refresh token
            if session.refresh_token and session.refresh_token in self._refresh_tokens:
                del self._refresh_tokens[session.refresh_token]

            return True

    def revoke_all_sessions(self, subject_id: str) -> int:
        """Revoke all sessions for a subject. Returns count revoked."""
        count = 0
        with self._lock:
            session_ids = self._subject_sessions.get(subject_id, [])
            for session_id in session_ids:
                session = self._sessions.get(session_id)
                if session and session.status == SessionStatus.ACTIVE:
                    session.status = SessionStatus.REVOKED
                    count += 1

                    if session.refresh_token and session.refresh_token in self._refresh_tokens:
                        del self._refresh_tokens[session.refresh_token]

        return count

    def lock_session(self, session_id: str) -> bool:
        """Lock a session (e.g., for security reasons)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False

            session.status = SessionStatus.LOCKED
            return True

    def unlock_session(self, session_id: str) -> bool:
        """Unlock a locked session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.status != SessionStatus.LOCKED:
                return False

            if session.is_expired():
                session.status = SessionStatus.EXPIRED
                return False

            session.status = SessionStatus.ACTIVE
            return True

    def get_subject_sessions(
        self,
        subject_id: str,
        include_inactive: bool = False,
    ) -> List[Session]:
        """Get all sessions for a subject."""
        with self._lock:
            session_ids = self._subject_sessions.get(subject_id, [])
            sessions = [
                self._sessions[sid]
                for sid in session_ids
                if sid in self._sessions
            ]

        if not include_inactive:
            sessions = [s for s in sessions if s.is_valid()]

        return sessions

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions. Returns count cleaned."""
        count = 0
        now = datetime.now(timezone.utc)

        with self._lock:
            for session_id, session in list(self._sessions.items()):
                if session.is_expired() or session.status in (
                    SessionStatus.EXPIRED, SessionStatus.REVOKED
                ):
                    # Only clean up sessions that have been expired for a while
                    if now - session.expires_at > timedelta(days=1):
                        del self._sessions[session_id]

                        if session.refresh_token in self._refresh_tokens:
                            del self._refresh_tokens[session.refresh_token]

                        if session.subject_id in self._subject_sessions:
                            self._subject_sessions[session.subject_id] = [
                                sid for sid in self._subject_sessions[session.subject_id]
                                if sid != session_id
                            ]

                        count += 1

        return count

    def get_active_session_count(self) -> int:
        """Get count of active sessions."""
        with self._lock:
            return sum(
                1 for s in self._sessions.values()
                if s.is_valid()
            )

    def extend_session(self, session_id: str, extension: timedelta) -> bool:
        """Extend a session's expiration time."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not session.is_valid():
                return False

            session.expires_at += extension
            return True
