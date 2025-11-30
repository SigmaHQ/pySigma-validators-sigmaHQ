from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.fields import (
    SigmahqUnknownFieldIssue,
    SigmahqUnknownFieldValidator,
)


def test_validator_SigmahqUnknownField_single():
    """Test with a single unknown field."""
    validator = SigmahqUnknownFieldValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test
description: Test
logsource:
    category: test
created: 2024-08-09
detection:
    sel:
        field: value
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnknownFieldIssue([detection_rule], ["created"])
    ]


def test_validator_SigmahqUnknownField_valid():
    """Test with only known fields."""
    validator = SigmahqUnknownFieldValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test
description: Test
logsource:
    category: test
date: 2024-08-09
detection:
    sel:
        field: value
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqUnknownField_mixed():
    """Test with both known and unknown fields."""
    validator = SigmahqUnknownFieldValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test
description: Test
logsource:
    category: test
date: 2024-08-09
unknown_field: value
detection:
    sel:
        field: value
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnknownFieldIssue([detection_rule], ["unknown_field"])
    ]


def test_validator_SigmahqUnknownField_empty_rule():
    """Test with an empty rule (edge case)."""
    validator = SigmahqUnknownFieldValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test
description: Test
logsource:
    category: test
detection:
    sel:
        field: value
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqUnknownField_correlation_rule_empty():
    """Test with an empty correlation rule (edge case)."""
    validator = SigmahqUnknownFieldValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(correlation_rule) == []
