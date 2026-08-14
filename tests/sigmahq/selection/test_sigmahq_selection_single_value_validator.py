from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.selection import (
    SigmahqSelectionSingleValueIssue,
    SigmahqSelectionSingleValueValidator,
)


def test_validator_SigmahqSelectionSingleValue_valid():
    validator = SigmahqSelectionSingleValueValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        field:
            - value1
            - value2
    condition: selection
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqSelectionSingleValue_invalid():
    validator = SigmahqSelectionSingleValueValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        field:
            - value1
    condition: selection
"""
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqSelectionSingleValueIssue)
    assert issues[0].selection == "selection"
    assert issues[0].field == "field"


def test_validator_SigmahqSelectionSingleValue_single_value_multiple_fields():
    validator = SigmahqSelectionSingleValueValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    selection:
        field1:
            - value1
        field2:
            - value2
            - value3
    condition: selection
"""
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert issues[0].field == "field1"


def test_validator_SigmahqSelectionSingleValue_valid_correlation():
    validator = SigmahqSelectionSingleValueValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: event_count
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(rule) == []
