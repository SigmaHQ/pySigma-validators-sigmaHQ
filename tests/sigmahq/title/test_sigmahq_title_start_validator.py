# tests/sigmahq/title/test_sigmahq_title_start_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.title import SigmahqTitleStartValidator, SigmahqTitleStartIssue

#
# Detection Rule Tests
#


def test_validator_SigmahqTitleStart_detect():
    """Test that titles starting with 'Detect ' are caught"""
    validator = SigmahqTitleStartValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Detect an Alert
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqTitleStartIssue([detection_rule])]


def test_validator_SigmahqTitleStart_detects():
    """Test that titles starting with 'Detects ' are caught"""
    validator = SigmahqTitleStartValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Detects something
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqTitleStartIssue([detection_rule])]


def test_validator_SigmahqTitleStart_valid():
    """Test that titles not starting with 'Detect' or 'Detects' pass validation"""
    validator = SigmahqTitleStartValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: This does not start with Detect
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


def test_validator_SigmahqTitleStart_valid_no_space():
    """Test that titles starting with 'Detect' or 'Detects' but without space don't trigger"""
    validator = SigmahqTitleStartValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Detection
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


def test_validator_SigmahqTitleStart_valid_correlation():
    """Test that correlation rules not starting with 'Detect' or 'Detects' pass validation"""
    validator = SigmahqTitleStartValidator()
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


def test_validator_SigmahqTitleStart_correlation_detect():
    """Test that correlation rules starting with 'Detect ' are caught"""
    validator = SigmahqTitleStartValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Detect a correlation
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
    assert validator.validate(correlation_rule) == [SigmahqTitleStartIssue([correlation_rule])]


def test_validator_SigmahqTitleStart_correlation_detects():
    """Test that correlation rules starting with 'Detects ' are caught"""
    validator = SigmahqTitleStartValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Detects a correlation
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
    assert validator.validate(correlation_rule) == [SigmahqTitleStartIssue([correlation_rule])]


def test_validator_SigmahqTitleStart_correlation_valid_no_space():
    """Test that correlation rules starting with 'Detect' or 'Detects' but without space don't trigger"""
    validator = SigmahqTitleStartValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Detection
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
