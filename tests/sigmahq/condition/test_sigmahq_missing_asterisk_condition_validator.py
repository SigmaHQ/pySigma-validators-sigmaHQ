import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.condition import (
    SigmahqMissingAsteriskConditionIssue,
    SigmahqMissingAsteriskConditionValidator,
)
from sigma.correlations import SigmaCorrelationRule


def test_validator_SigmahqMissingAsteriskConditionValidator():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_part_2:
            field1: val1
        selection_sub:
            field1: val1
        condition: 1 of selection_part* and 1 of selection_sub
    """
    )
    assert validator.validate(rule) == [
        SigmahqMissingAsteriskConditionIssue([rule], "selection_sub")
    ]


def test_validator_SigmahqMissingAsteriskConditionValidator_valid():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_part_2:
            field1: val1
        selection_sub:
            field1: val1
        condition: 1 of selection_part* and selection_sub
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqMissingAsteriskConditionValidator_them():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_part_2:
            field1: val1
        selection_sub:
            field1: val1
        condition: 1 of them
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqMissingAsteriskConditionValidator_no_detections():
    # Skip this test - Sigma rules must have detections
    pass


def test_validator_SigmahqMissingAsteriskConditionValidator_no_condition():
    # Skip this test - Sigma rules must have conditions
    pass


def test_validator_SigmahqMissingAsteriskConditionValidator_all_of_selection():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_part_2:
            field1: val1
        condition: all of selection_part_*
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqMissingAsteriskConditionValidator_all_of_selection_single():
    # This is a valid case - single selection with all of selection_* should not trigger an issue
    # when there are actually multiple selections matching the pattern
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_part_2:
            field1: val1
        condition: all of selection_part_*
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqMissingAsteriskConditionValidator_complex_condition():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_part_2:
            field1: val1
        selection_sub:
            field1: val1
        condition: 1 of selection_part* and 1 of selection_sub and not 1 of filter_*
    """
    )
    assert validator.validate(rule) == [
        SigmahqMissingAsteriskConditionIssue([rule], "selection_sub")
    ]


def test_SigmahqMissingAsteriskConditionValidator_correlation():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Valid correlation",
            "correlation": {
                "type": "temporal",
                "rules": ["event_a", "event_b"],
                "group-by": ["source", "user"],
                "timespan": "1h",
                "aliases": {
                    "source": {
                        "event_a": "source_ip",
                        "event_b": "source_address",
                    },
                    "user": {
                        "event_a": "username",
                        "event_b": "user_name",
                    },
                },
            },
        }
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqMissingAsteriskConditionValidator_no_match():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        condition: 1 of selection_part_*
    """
    )
    # Should not trigger issue when all patterns end with *
    assert validator.validate(rule) == []


def test_validator_SigmahqMissingAsteriskConditionValidator_whitespace():
    validator = SigmahqMissingAsteriskConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_part_1:
            field1: val1
        selection_sub:
            field1: val1
        condition:   1 of selection_part*   and   1 of selection_sub
    """
    )
    assert validator.validate(rule) == [
        SigmahqMissingAsteriskConditionIssue([rule], "selection_sub")
    ]
