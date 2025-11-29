# tests/sigmahq/tags/test_sigmahq_tags_detection_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.tags import (
    SigmahqTagsDetectionIssue,
    SigmahqTagsDetectionValidator,
)

#
# Detection Rule Tests
#


def test_validator_SigmahqTagsDetection():
    validator = SigmahqTagsDetectionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-emerging-threats/invalid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqTagsDetectionIssue([rule], tag="emerging-threats")]


def test_validator_SigmahqTagsDetection_valid():
    validator = SigmahqTagsDetectionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-emerging-threats/valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsDetection_no_folders():
    validator = SigmahqTagsDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - detection.threat-hunting
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []


#
# Correlation Rule Tests
#


def test_validator_SigmahqTagsDetection_correlation():
    validator = SigmahqTagsDetectionValidator()
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


def test_validator_SigmahqTagsDetection_correlation_with_detection_tag():
    validator = SigmahqTagsDetectionValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
tags:
    - detection.emerging-threats
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
