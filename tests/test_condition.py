import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.condition import (
    SigmahqOfthemConditionIssue,
    SigmahqOfthemConditionValidator,
    SigmahqOfselectionConditionIssue,
    SigmahqOfselectionConditionValidator,
    SigmahqMissingAsteriskConditionIssue,
    SigmahqMissingAsteriskConditionValidator,
)
from sigma.correlations import SigmaCorrelationRule


def test_validator_SigmahqOfthemConditionValidator_1():
    validator = SigmahqOfthemConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        condition: 1 of them
    """
    )
    assert validator.validate(rule) == [SigmahqOfthemConditionIssue([rule])]


def test_validator_SigmahqOfthemConditionValidator_all():
    validator = SigmahqOfthemConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        condition: all of them
    """
    )
    assert validator.validate(rule) == [SigmahqOfthemConditionIssue([rule])]


def test_validator_SigmahqOfthemConditionValidator_all_valid():
    validator = SigmahqOfthemConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        selection2:
            field1: val2
        condition: all of them
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqOfthemConditionValidator_valid():
    validator = SigmahqOfselectionConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        selection2:
            field2: val2
        condition: all of them
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqOfselectionConditionValidator():
    validator = SigmahqOfselectionConditionValidator()
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
        sub_1:
            field1: val1   
        condition: 1 of selection_part* and 1 of sub_*
    """
    )
    assert validator.validate(rule) == [SigmahqOfselectionConditionIssue(rule, "sub_*")]


def test_validator_SigmahqOfselectionConditionValidator_valid():
    validator = SigmahqOfselectionConditionValidator()
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
        selection_sub_1:
            field1: val1   
        condition: 1 of selection_part* and selection_sub_1
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqOfselectionConditionValidator_filter():
    validator = SigmahqOfselectionConditionValidator()
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
        filter_1:
            field1: val1   
        condition: 1 of selection_part* and not 1 of filter_*
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqOfselectionConditionValidator_selection():
    validator = SigmahqOfselectionConditionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection_lol:
            field1: val1 
        condition: 1 of selection_*
    """
    )
    assert validator.validate(rule) == []


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
        SigmahqMissingAsteriskConditionIssue(rule, "selection_sub")
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


def SigmahqOfthemConditionValidator_correlation():
    validator = SigmahqOfthemConditionValidator()
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


def SigmahqOfselectionConditionValidator_correlation():
    validator = SigmahqOfselectionConditionValidator()
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


def SigmahqMissingAsteriskConditionValidator_correlation():
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
