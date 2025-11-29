# tests/sigmahq/title/test_sigmahq_title_end_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.title import SigmahqTitleEndValidator, SigmahqTitleEndIssue

#
# Detection Rule Tests
#


def test_validator_SigmahqTitleEnd():
    """Test that detection rules with titles ending in dot fail validation"""
    validator = SigmahqTitleEndValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Title end with a.
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqTitleEndIssue([detection_rule])]


def test_validator_SigmahqTitleEnd_valid():
    """Test that detection rules with titles not ending in dot pass validation"""
    validator = SigmahqTitleEndValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Title does not end with a dot
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTitleEnd_single_dot():
    """Test that a detection rule with title that is just a dot fails validation"""
    validator = SigmahqTitleEndValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: .
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqTitleEndIssue([detection_rule])]


def test_validator_SigmahqTitleEnd_empty_title():
    """Test that detection rule with empty title passes validation (doesn't end with dot)"""
    validator = SigmahqTitleEndValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: ""
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


#
# Correlation Rule Tests
#


def test_validator_SigmahqTitleEnd_valid_correlation():
    """Test that correlation rules not ending in dot pass validation"""
    validator = SigmahqTitleEndValidator()
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


def test_validator_SigmahqTitleEnd_correlation():
    """Test that correlation rules with titles ending in dot are caught"""
    validator = SigmahqTitleEndValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation.
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
    assert validator.validate(correlation_rule) == [SigmahqTitleEndIssue([correlation_rule])]


def test_validator_SigmahqTitleEnd_correlation_single_dot():
    """Test that correlation rules with title that is just a dot fail validation"""
    validator = SigmahqTitleEndValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: .
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
    assert validator.validate(correlation_rule) == [SigmahqTitleEndIssue([correlation_rule])]
