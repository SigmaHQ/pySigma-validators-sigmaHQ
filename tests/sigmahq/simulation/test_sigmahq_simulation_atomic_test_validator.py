import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.simulation import (
    SigmahqSimulationAtomicTestExistsValidator,
    SigmahqSimulationUnknownAtomicTestIssue,
    SigmahqSimulationValidator,
)

KNOWN_GUID = "11111111-1111-4111-8111-111111111111"
KNOWN_NAME = "PowerShell Execute a Script"
# listed twice in the index, once per tactic, always with the same name
DUPLICATED_GUID = "33333333-3333-4333-8333-333333333333"
UNKNOWN_GUID = "99999999-9999-4999-8999-999999999999"


def create_rule(entries: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        f"""title: Test Rule
status: test
date: 2024-01-01
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        candle|exists: true
    condition: sel
simulation:
{entries}"""
    )


def entry(guid: str = KNOWN_GUID, name: str = KNOWN_NAME, technique: str = "T1059.001") -> str:
    return (
        "    - type: atomic-red-team\n"
        f"      name: {name}\n"
        f"      technique: {technique}\n"
        f"      atomic_guid: {guid}\n"
    )


def test_validator_atomic_test_exists_known_guid():
    rule = create_rule(entry())
    assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == []


def test_validator_atomic_test_exists_guid_repeated_in_index():
    rule = create_rule(
        entry(guid=DUPLICATED_GUID, name="'chattr - Remove immutable file attribute'")
    )
    assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == []


def test_validator_atomic_test_exists_unknown_guid():
    rule = create_rule(entry(guid=UNKNOWN_GUID))
    assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == [
        SigmahqSimulationUnknownAtomicTestIssue([rule], atomic_guid=UNKNOWN_GUID)
    ]


def test_validator_atomic_test_exists_reports_every_unknown_entry():
    rule = create_rule(entry() + entry(guid=UNKNOWN_GUID))
    assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == [
        SigmahqSimulationUnknownAtomicTestIssue([rule], atomic_guid=UNKNOWN_GUID)
    ]


def test_validator_atomic_test_exists_ignores_simulation_absent():
    rule = SigmaRule.from_yaml(
        """title: Test Rule
status: test
date: 2024-01-01
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )
    assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == []


def test_validator_atomic_test_exists_ignores_malformed_entries():
    """Structural problems are reported by SigmahqSimulationValidator, not here."""
    rule = create_rule("    - some string\n    - type: atomic-red-team\n")
    assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == []


@pytest.fixture
def unreachable_index(monkeypatch):
    """Make the Atomic Red Team index unreachable, as during a network outage."""

    def raise_unreachable(self):
        raise RuntimeError("Failed to load data: <urlopen error timed out>")

    monkeypatch.setattr(
        "sigma.validators.sigmahq.data.data_atomic_red_team._AtomicRedTeamLoader._load_cached",
        raise_unreachable,
    )


def test_validator_atomic_test_exists_silent_when_index_unreachable(unreachable_index):
    """An unreachable index must not fail every rule, and must be reported."""
    rule = create_rule(entry(guid=UNKNOWN_GUID))
    with pytest.warns(UserWarning, match="index unavailable"):
        assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == []


def test_validator_atomic_test_exists_empty_index_warns_and_skips(monkeypatch):
    """An empty index (HTML 404 page, moved file) must not flag every rule."""

    def raise_empty(self):
        raise RuntimeError(
            "Atomic Red Team index is empty; the upstream file is likely unreachable"
        )

    monkeypatch.setattr(
        "sigma.validators.sigmahq.data.data_atomic_red_team._AtomicRedTeamLoader._load_cached",
        raise_empty,
    )
    rule = create_rule(entry())
    with pytest.warns(UserWarning, match="index unavailable"):
        assert SigmahqSimulationAtomicTestExistsValidator().validate(rule) == []


@pytest.mark.parametrize(
    "guid",
    [
        "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",  # version 1
        "886313e1-3b8a-5372-9b90-0c9aee199e5d",  # version 5
    ],
)
def test_validator_atomic_test_exists_uuid_must_be_v4(guid):
    """Every GUID of the index is a v4 UUID, so another version cannot resolve."""
    rule = create_rule(entry(guid=f"'{guid}'"))
    assert [type(i).__name__ for i in SigmahqSimulationValidator().validate(rule)] == [
        "SigmahqSimulationInvalidAtomicGuidIssue"
    ]
    exists = SigmahqSimulationAtomicTestExistsValidator().validate(rule)
    assert [type(i).__name__ for i in exists] == ["SigmahqSimulationUnknownAtomicTestIssue"]
