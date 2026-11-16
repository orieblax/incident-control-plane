"""Domain-level exceptions independent of transport or persistence."""

from __future__ import annotations


class DomainError(Exception):
    """Base error for domain rule violations."""


class NotFoundError(DomainError):
    """Raised when a requested aggregate or entity does not exist."""


class AuthorizationError(DomainError):
    """Raised when the principal lacks permission for the operation."""


class InvalidStateTransitionError(DomainError):
    """Raised when an incident transition violates the state machine."""


class ApprovalRequiredError(DomainError):
    """Raised when a high-risk operation requires explicit confirmation."""


class InvalidApprovalTokenError(DomainError):
    """Raised when an approval token is invalid, expired, or already used."""


class ValidationError(DomainError):
    """Raised when domain invariants are violated."""
