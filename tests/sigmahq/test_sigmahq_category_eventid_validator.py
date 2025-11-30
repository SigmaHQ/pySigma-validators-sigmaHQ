from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqCategoryEventIdIssue,
    SigmahqCategoryEventIdValidator,
)


def test_validator_SigmahqCategoryEventId():
    validator = SigmahqCategoryEventIdValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: ps_module
detection:
    sel:
        field: path\\*something
        EventID: 4103
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqCategoryEventIdIssue([detection_rule])]


def test_validator_SigmahqCategoryEventId_valid():
    validator = SigmahqCategoryEventIdValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: ps_module
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqCategoryEventId_other():
    validator = SigmahqCategoryEventIdValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        field: path\\*something
        EventID: 4103
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqCategoryEventId_multiple_eventids():
    validator = SigmahqCategoryEventIdValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: ps_module
detection:
    sel:
        field: path\\*something
        EventID: 
            - 4103
            - 4104
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqCategoryEventIdIssue([detection_rule])]


def test_validator_SigmahqCategoryEventId_different_category():
    validator = SigmahqCategoryEventIdValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field: path\\*something
        EventID: 4103
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqCategoryEventIdIssue([detection_rule])]


def test_validator_SigmahqCategoryEventId_no_category():
    validator = SigmahqCategoryEventIdValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
detection:
    sel:
        field: path\\*something
        EventID: 4103
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqCategoryEventId_correlation_valid():
    validator = SigmahqCategoryEventIdValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    author: Test Author
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
