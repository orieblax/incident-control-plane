"""Unit tests for the incident lifecycle state machine."""

from __future__ import annotations

import pytest

from src.domain.exceptions import InvalidStateTransitionError
from src.domain.models import IncidentStatus
from src.domain.state_machine import validate_transition


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (IncidentStatus.TRIGGERED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.TRIGGERED, IncidentStatus.RESOLVED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED),
        (IncidentStatus.MITIGATED, IncidentStatus.RESOLVED),
        (IncidentStatus.MITIGATED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING),
    ],
)
def test_valid_transitions(current: IncidentStatus, target: IncidentStatus) -> None:
    validate_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (IncidentStatus.TRIGGERED, IncidentStatus.TRIGGERED),
        (IncidentStatus.TRIGGERED, IncidentStatus.MITIGATED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.TRIGGERED),
        (IncidentStatus.MITIGATED, IncidentStatus.TRIGGERED),
        (IncidentStatus.RESOLVED, IncidentStatus.MITIGATED),
        (IncidentStatus.RESOLVED, IncidentStatus.TRIGGERED),
    ],
)
def test_invalid_transitions_raise(
    current: IncidentStatus, target: IncidentStatus
) -> None:
    with pytest.raises(InvalidStateTransitionError):
        validate_transition(current, target)
