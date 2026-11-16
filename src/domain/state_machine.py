"""Incident lifecycle state machine and transition validation."""

from __future__ import annotations

from src.domain.exceptions import InvalidStateTransitionError
from src.domain.models import IncidentStatus

ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.TRIGGERED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {IncidentStatus.MITIGATED, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.MITIGATED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.INVESTIGATING}),
}


def validate_transition(current: IncidentStatus, target: IncidentStatus) -> None:
    """Validate an incident state transition against the domain state machine."""
    if current == target:
        raise InvalidStateTransitionError(
            f"Incident is already in '{current.value}' status."
        )
    allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        allowed_list = ", ".join(sorted(s.value for s in allowed)) or "none"
        raise InvalidStateTransitionError(
            f"Invalid transition '{current.value}' -> '{target.value}'. "
            f"Allowed targets from '{current.value}': {allowed_list}."
        )
