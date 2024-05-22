import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.condition import (
    SigmahqOfthemConditionIssue,
    SigmahqOfthemConditionValidator,
    SigmahqOfselectionConditionIssue,
    SigmahqOfselectionConditionValidator,
    SigmahqNoasterixofselectionConditionIssue,
    SigmahqNoasterixofselectionConditionValidator,
)


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
        selection_sub_1:
            field1: val1   
        condition: 1 of selection_part* and 1 of selection_sub_*
    """
    )
    assert validator.validate(rule) == [
        SigmahqOfselectionConditionIssue(rule, "selection_sub_*")
    ]


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


def test_validator_SigmahqNoasterixofselectionConditionValidator():
    validator = SigmahqNoasterixofselectionConditionValidator()
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
        SigmahqNoasterixofselectionConditionIssue(rule, "selection_sub")
    ]


def test_validator_SigmahqNoasterixofselectionConditionValidator_valid():
    validator = SigmahqNoasterixofselectionConditionValidator()
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
