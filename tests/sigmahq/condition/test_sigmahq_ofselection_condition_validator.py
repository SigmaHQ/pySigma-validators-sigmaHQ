from sigma.rule import SigmaRule
from sigma.validators.sigmahq.condition import (
    SigmahqOfselectionConditionIssue,
    SigmahqOfselectionConditionValidator,
)
from sigma.correlations import SigmaCorrelationRule


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
    assert validator.validate(rule) == [SigmahqOfselectionConditionIssue([rule], "sub_*")]


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


def test_validator_SigmahqOfselectionConditionValidator_all_of_selection():
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
        condition: all of selection_part_*
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqOfselectionConditionValidator_all_of_selection_single():
    # This is a valid case - single selection with all of selection_* should not trigger an issue
    # when there are actually multiple selections matching the pattern
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
        condition: all of selection_part_*
    """
    )
    assert validator.validate(rule) == []


def test_SigmahqOfselectionConditionValidator_correlation():
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


def test_validator_SigmahqOfselectionConditionValidator_no_match():
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
        condition: 1 of selection_nonexistent_*
    """
    )
    # Should not trigger issue when no selections match the pattern
    assert validator.validate(rule) == []


def test_validator_SigmahqOfselectionConditionValidator_multiple_patterns():
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
        sub_2:
            field1: val1
        condition: 1 of selection_part* and 1 of sub_*
    """
    )
    # Should not trigger issue when multiple selections match the pattern
    assert validator.validate(rule) == []
