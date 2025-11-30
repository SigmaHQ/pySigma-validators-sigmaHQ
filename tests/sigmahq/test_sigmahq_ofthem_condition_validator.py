from sigma.rule import SigmaRule
from sigma.validators.sigmahq.condition import (
    SigmahqOfthemConditionIssue,
    SigmahqOfthemConditionValidator,
)
from sigma.correlations import SigmaCorrelationRule


def test_validator_SigmahqOfthemConditionValidator_1():
    validator = SigmahqOfthemConditionValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [SigmahqOfthemConditionIssue([detection_rule])]


def test_validator_SigmahqOfthemConditionValidator_all():
    validator = SigmahqOfthemConditionValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [SigmahqOfthemConditionIssue([detection_rule])]


def test_validator_SigmahqOfthemConditionValidator_all_valid():
    validator = SigmahqOfthemConditionValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_SigmahqOfthemConditionValidator_correlation():
    validator = SigmahqOfthemConditionValidator()
    correlation_rule = SigmaCorrelationRule.from_dict(
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
    assert validator.validate(correlation_rule) == []


def test_validator_SigmahqOfthemConditionValidator_whitespace():
    validator = SigmahqOfthemConditionValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        selection1:
            field1: val1
        condition:   1 of them
    """
    )
    assert validator.validate(detection_rule) == [SigmahqOfthemConditionIssue([detection_rule])]


def test_validator_SigmahqOfthemConditionValidator_1_valid():
    validator = SigmahqOfthemConditionValidator()
    detection_rule = SigmaRule.from_yaml(
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
        condition: 1 of them
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqOfthemConditionValidator_correlation_invalid():
    validator = SigmahqOfthemConditionValidator()
    correlation_rule = SigmaCorrelationRule.from_dict(
        {
            "title": "Invalid correlation",
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
    assert validator.validate(correlation_rule) == []
