import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.condition import (
    OfthemConditionIssue,
    OfthemConditionValidator,
)



def test_validator_OfthemConditionValidator_1():
    validator = OfthemConditionValidator()
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
    assert validator.validate(rule) == [OfthemConditionIssue([rule])]

def test_validator_OfthemConditionValidator_all():
    validator = OfthemConditionValidator()
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
    assert validator.validate(rule) == [OfthemConditionIssue([rule])]

def test_validator_OfthemConditionValidator_valid():
    validator = OfthemConditionValidator()
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
    assert validator.validate(rule) == [OfthemConditionIssue([rule])]