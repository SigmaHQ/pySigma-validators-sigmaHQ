from datetime import datetime

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqStatusToHighIssue,
    SigmahqStatusToHighValidator,
)

#
# Detection Rule Tests
#


def test_validator_SigmahqStatusToHigh():
    validator = SigmahqStatusToHighValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    rule.date = datetime.now().date()
    assert validator.validate(rule) == [SigmahqStatusToHighIssue([rule])]


def test_validator_SigmahqStatusToHigh_valid():
    validator = SigmahqStatusToHighValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqStatusToHigh_with_regression_valid():
    validator = SigmahqStatusToHighValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: test
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    regression_tests_path: regression/rule/test_rule.yml
    """
    )
    rule.date = datetime.now().date()
    assert validator.validate(rule) == []


#
# Correlation Rule Tests
#
