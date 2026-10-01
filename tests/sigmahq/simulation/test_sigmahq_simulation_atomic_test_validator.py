import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.simulation import (
    SigmahqSimulationAtomicTestExistsValidator,
    SigmahqSimulationAtomicTestNameIssue,
    SigmahqSimulationAtomicTestNameValidator,
    SigmahqSimulationUnknownAtomicTestIssue,
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


def entry(guid: str = KNOWN_GUID, name: str = KNOWN_NAME) -> str:
    return (
        "    - type: atomic-red-team\n"
        f"      name: {name}\n"
        "      technique: T1059.001\n"
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


def test_validator_atomic_test_name_matches():
    rule = create_rule(entry())
    assert SigmahqSimulationAtomicTestNameValidator().validate(rule) == []


@pytest.mark.parametrize("name", ["powershell execute a script", "PowerShell  Execute  a Script "])
def test_validator_atomic_test_name_case_and_whitespace_tolerated(name):
    rule = create_rule(entry(name=f"'{name}'"))
    assert SigmahqSimulationAtomicTestNameValidator().validate(rule) == []


def test_validator_atomic_test_name_similar_tolerated():
    """'Disable Windows Event Logging' vs its slightly different spelling."""
    rule = create_rule(
        entry(
            guid="55555555-5555-4555-8555-555555555555",
            name="'Disable Windows Event Loggin'",
        )
    )
    assert SigmahqSimulationAtomicTestNameValidator().validate(rule) == []


def test_validator_atomic_test_name_divergent():
    rule = create_rule(entry(name="'RDP to DomainController'"))
    assert SigmahqSimulationAtomicTestNameValidator().validate(rule) == [
        SigmahqSimulationAtomicTestNameIssue(
            [rule], name="RDP to DomainController", expected_name=KNOWN_NAME
        )
    ]


def test_validator_atomic_test_name_threshold_is_configurable():
    validator = SigmahqSimulationAtomicTestNameValidator(name_similarity_threshold=1.0)
    rule = create_rule(
        entry(
            guid="55555555-5555-4555-8555-555555555555",
            name="'Disable Windows Event Loggin'",
        )
    )
    assert validator.validate(rule) == [
        SigmahqSimulationAtomicTestNameIssue(
            [rule],
            name="Disable Windows Event Loggin",
            expected_name="Disable Windows Event Logging",
        )
    ]


def test_validator_atomic_test_name_technique_is_not_compared():
    """ART master renumbered T1562.001 to T1685, so technique must not be checked."""
    rule = create_rule(
        entry(guid="55555555-5555-4555-8555-555555555555", name="'Disable Windows Event Logging'")
    )
    rule.custom_attributes["simulation"][0]["technique"] = "T1562.001"
    assert SigmahqSimulationAtomicTestNameValidator().validate(rule) == []


def test_validator_atomic_test_name_unknown_guid_is_skipped():
    rule = create_rule(entry(guid=UNKNOWN_GUID, name="'RDP to DomainController'"))
    assert SigmahqSimulationAtomicTestNameValidator().validate(rule) == []


def test_validator_atomic_test_name_reports_every_divergent_entry():
    rule = create_rule(entry(name="'First Wrong Name'") + entry(name="'Second Wrong Name'"))
    issues = SigmahqSimulationAtomicTestNameValidator().validate(rule)
    assert [i.name for i in issues] == ["First Wrong Name", "Second Wrong Name"]
    assert all(i.expected_name == KNOWN_NAME for i in issues)
