# tests/test_sigmahq_tags_detection_validator.py

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.tags import (
    SigmahqTagsDetectionIssue,
    SigmahqTagsDetectionValidator,
)


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
