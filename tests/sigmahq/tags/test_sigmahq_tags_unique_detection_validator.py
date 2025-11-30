from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.tags import (
    SigmahqTagsUniqueDetectionIssue,
    SigmahqTagsUniqueDetectionValidator,
)


def test_validator_SigmahqTagsUniqueDetection():
    validator = SigmahqTagsUniqueDetectionValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - detection.dfir
    - detection.threat-hunting
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqTagsUniqueDetectionIssue([detection_rule])]


def test_validator_SigmahqTagsUniqueDetection_valid():
    validator = SigmahqTagsUniqueDetectionValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - detection.dfir
    - tlp.clean
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTagsUniqueDetection_correlation():
    validator = SigmahqTagsUniqueDetectionValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
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


def test_validator_SigmahqTagsUniqueDetection_correlation_with_multiple_detection_tags():
    validator = SigmahqTagsUniqueDetectionValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
tags:
    - detection.dfir
    - detection.threat-hunting
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
    assert validator.validate(correlation_rule) == [
        SigmahqTagsUniqueDetectionIssue([correlation_rule])
    ]
