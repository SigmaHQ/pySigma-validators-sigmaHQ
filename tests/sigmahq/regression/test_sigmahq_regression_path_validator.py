import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.regression import (
    SigmahqRegressionPathInvalidFormatIssue,
    SigmahqRegressionPathNotStringIssue,
    SigmahqRegressionPathValidator,
)

VALID_PATH = "regression_data/rules/windows/process_creation/proc_creation_win_test/info.yml"


def create_rule(path_block: str) -> SigmaRule:
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
{path_block}"""
    )


def test_validator_regression_path_absent():
    rule = create_rule("")
    assert SigmahqRegressionPathValidator().validate(rule) == []


@pytest.mark.parametrize(
    "path",
    [
        VALID_PATH,
        "regression_data/rules-emerging-threats/2025/Malware/X/win_x/info.yml",
        "regression_data/rules-threat-hunting/windows/file/file_event/win_x/info.yml",
        "regression_data/rules-dfir/x/win_x/info.yml",
        "regression_data/rules-compliance/other/win_x/info.yml",
    ],
)
def test_validator_regression_path_valid(path):
    rule = create_rule(f"regression_tests_path: {path}\n")
    assert SigmahqRegressionPathValidator().validate(rule) == []


@pytest.mark.parametrize(
    "path",
    [
        "info.yml",
        "regression_data/info.yml",
        "regression_data/rules/info.yml",
        "regression_data/rules-emerging-threats/info.yml",
        "regression_data/rules/windows/process_creation/win_test/info.yaml",
        "regression_data/rules/windows/process_creation/win_test/",
        "regression_data/rules/windows/process_creation/win_test/data.json",
        "rules/windows/process_creation/win_test/info.yml",
        "regression_data/unknown_tree/win_x/info.yml",
        " regression_data/rules/windows/win_x/info.yml",
    ],
)
def test_validator_regression_path_invalid_format(path):
    rule = create_rule(f"regression_tests_path: '{path}'\n")
    assert SigmahqRegressionPathValidator().validate(rule) == [
        SigmahqRegressionPathInvalidFormatIssue([rule], path=path)
    ]


@pytest.mark.parametrize("value", ["[]", "{}", "true", "123"])
def test_validator_regression_path_not_a_string(value):
    rule = create_rule(f"regression_tests_path: {value}\n")
    assert SigmahqRegressionPathValidator().validate(rule) == [
        SigmahqRegressionPathNotStringIssue([rule])
    ]


def test_validator_regression_path_not_required_for_stable_rule():
    """Only the shape is checked when the field is present; its absence is not an issue."""
    rule = SigmaRule.from_yaml(
        """title: Test Rule
status: stable
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
    assert SigmahqRegressionPathValidator().validate(rule) == []


def test_validator_regression_path_ignores_other_custom_attributes():
    rule = create_rule(
        "simulation:\n"
        "    - type: atomic-red-team\n"
        "      name: Some Atomic\n"
        "      technique: T1059.001\n"
        "      atomic_guid: 11111111-2222-4333-8444-555555555555\n"
    )
    assert SigmahqRegressionPathValidator().validate(rule) == []
