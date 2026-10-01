import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.simulation import (
    SigmahqSimulationEmptyIssue,
    SigmahqSimulationEntryNotDictIssue,
    SigmahqSimulationInvalidAtomicGuidIssue,
    SigmahqSimulationInvalidNameIssue,
    SigmahqSimulationInvalidTechniqueIssue,
    SigmahqSimulationInvalidTypeIssue,
    SigmahqSimulationMissingKeyIssue,
    SigmahqSimulationNotListIssue,
    SigmahqSimulationUnknownKeyIssue,
    SigmahqSimulationValidator,
)

VALID_ENTRY = """
    - type: atomic-red-team
      name: Set a file's access timestamp
      technique: T1070.006
      atomic_guid: 5f9113d5-ed75-47ed-ba23-ea3573d05810
"""


def create_rule(simulation_block: str) -> SigmaRule:
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
{simulation_block}"""
    )


def test_validator_simulation_absent():
    rule = create_rule("")
    assert SigmahqSimulationValidator().validate(rule) == []


def test_validator_simulation_valid_single_entry():
    rule = create_rule(f"simulation:{VALID_ENTRY}")
    assert SigmahqSimulationValidator().validate(rule) == []


def test_validator_simulation_valid_multiple_entries():
    rule = create_rule(
        "simulation:"
        + VALID_ENTRY
        + """
    - type: atomic-red-team
      name: Set a file's modification timestamp
      technique: T1070.006
      atomic_guid: 20ef1523-8758-4898-b5a2-d026cc3d2c52
"""
    )
    assert SigmahqSimulationValidator().validate(rule) == []


def test_validator_simulation_technique_parent_only():
    rule = create_rule(
        "simulation:\n"
        "    - type: atomic-red-team\n"
        "      name: Windows - Disable the SR scheduled task\n"
        "      technique: T1490\n"
        "      atomic_guid: 1c68c68d-83a4-4981-974e-8993055fa034\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == []


def test_validator_simulation_not_a_list():
    rule = create_rule("simulation: atomic-red-team\n")
    assert SigmahqSimulationValidator().validate(rule) == [SigmahqSimulationNotListIssue([rule])]


def test_validator_simulation_empty_list():
    rule = create_rule("simulation: []\n")
    assert SigmahqSimulationValidator().validate(rule) == [SigmahqSimulationEmptyIssue([rule])]


def test_validator_simulation_entry_not_a_dict():
    rule = create_rule("simulation:\n    - some string\n")
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationEntryNotDictIssue([rule])
    ]


def test_validator_simulation_missing_keys():
    rule = create_rule("simulation:\n    - type: atomic-red-team\n      name: Some Atomic\n")
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationMissingKeyIssue([rule], missing_keys=["atomic_guid", "technique"])
    ]


def test_validator_simulation_missing_key_reports_only_the_missing_key():
    """A missing key must not also trigger that key's value check."""
    rule = create_rule(
        "simulation:\n    - type: atomic-red-team\n      name: Some Atomic\n"
        "      technique: T1059.001\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationMissingKeyIssue([rule], missing_keys=["atomic_guid"])
    ]


def test_validator_simulation_unknown_keys():
    rule = create_rule(f"simulation:{VALID_ENTRY}      executor: cmd\n      platform: windows\n")
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationUnknownKeyIssue([rule], unknown_keys=["executor", "platform"])
    ]


@pytest.mark.parametrize(
    "sim_type",
    [
        "atomic red team",
        "Atomic-Red-Team",
        "atomic-red-team ",
        "caldera",
        "",
    ],
)
def test_validator_simulation_invalid_type(sim_type):
    rule = create_rule(
        f"simulation:\n    - type: '{sim_type}'\n      name: Some Atomic\n"
        "      technique: T1059.001\n      atomic_guid: 11111111-2222-4333-8444-555555555555\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidTypeIssue([rule], type_value=sim_type)
    ]


@pytest.mark.parametrize("name", ["''", "'   '", "123", "true"])
def test_validator_simulation_invalid_name(name):
    rule = create_rule(
        f"simulation:\n    - type: atomic-red-team\n      name: {name}\n"
        "      technique: T1059.001\n      atomic_guid: 11111111-2222-4333-8444-555555555555\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidNameIssue([rule])
    ]


def test_validator_simulation_null_name():
    rule = create_rule(
        "simulation:\n    - type: atomic-red-team\n      name: null\n"
        "      technique: T1059.001\n      atomic_guid: 11111111-2222-4333-8444-555555555555\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidNameIssue([rule])
    ]


@pytest.mark.parametrize(
    "technique",
    ["t1059", "'T1059.0011'", "1059", "T1059-001", "T-1059.001", "''", "true"],
)
def test_validator_simulation_invalid_technique(technique):
    rule = create_rule(
        f"simulation:\n    - type: atomic-red-team\n      name: Some Atomic\n"
        f"      technique: {technique}\n"
        "      atomic_guid: 11111111-2222-4333-8444-555555555555\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidTechniqueIssue(
            [rule], technique=str(rule.custom_attributes["simulation"][0]["technique"])
        )
    ]


@pytest.mark.parametrize(
    "guid",
    ["not-a-uuid", "'11111111-2222-4333-8444-55555555555'", "''", "123"],
)
def test_validator_simulation_invalid_atomic_guid(guid):
    rule = create_rule(
        f"simulation:\n    - type: atomic-red-team\n      name: Some Atomic\n"
        f"      technique: T1059.001\n      atomic_guid: {guid}\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidAtomicGuidIssue(
            [rule], atomic_guid=str(rule.custom_attributes["simulation"][0]["atomic_guid"])
        )
    ]


def test_validator_simulation_atomic_guid_unquoted_is_an_int_and_rejected():
    rule = create_rule(
        "simulation:\n    - type: atomic-red-team\n      name: Some Atomic\n"
        "      technique: T1059.001\n      atomic_guid: 11111111222243338444555555555555\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidAtomicGuidIssue(
            [rule], atomic_guid="11111111222243338444555555555555"
        )
    ]


def test_validator_simulation_atomic_guid_without_dashes_quoted_is_accepted():
    rule = create_rule(
        "simulation:\n    - type: atomic-red-team\n      name: Some Atomic\n"
        "      technique: T1059.001\n      atomic_guid: '5f9113d5ed7547edba23ea3573d05810'\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == []


def test_validator_simulation_collects_all_issues_across_entries():
    rule = create_rule(
        "simulation:\n"
        "    - type: atomic red team\n"
        "      name: Some Atomic\n"
        "      technique: T1059.001\n"
        "      atomic_guid: not-a-uuid\n"
        "    - type: atomic-red-team\n"
        "      name: Another Atomic\n"
        "      technique: nope\n"
        "      atomic_guid: 20ef1523-8758-4898-b5a2-d026cc3d2c52\n"
    )
    assert SigmahqSimulationValidator().validate(rule) == [
        SigmahqSimulationInvalidTypeIssue([rule], type_value="atomic red team"),
        SigmahqSimulationInvalidAtomicGuidIssue([rule], atomic_guid="not-a-uuid"),
        SigmahqSimulationInvalidTechniqueIssue([rule], technique="nope"),
    ]
