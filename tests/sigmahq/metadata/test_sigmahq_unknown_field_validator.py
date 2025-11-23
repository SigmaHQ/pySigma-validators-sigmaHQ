from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqUnknownFieldIssue,
    SigmahqUnknownFieldValidator,
)


def test_validator_SigmahqUnknownField_single():
    """Test with a single unknown field."""
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqUnknownFieldIssue([rule], ["created"])]


def test_validator_SigmahqUnknownField_valid():
    """Test with only known fields."""
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqUnknownField_mixed():
    """Test with both known and unknown fields."""
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqUnknownFieldIssue([rule], ["unknown_field"])]


def test_validator_SigmahqUnknownField_empty_rule():
    """Test with an empty rule (edge case)."""
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqUnknownField_invalid_rule():
    """Test with an invalid rule (no detection section)."""
    validator = SigmahqUnknownFieldValidator()
    try:
        rule = SigmaRule.from_yaml(
            """
title: Test
description: Test
logsource:
    category: test
invalid_field: value
"""
        )
    except ValueError:
        rule = None

    assert (
        rule is None
    )  # This will ensure the rule creation failed as expected due to invalid structure.
