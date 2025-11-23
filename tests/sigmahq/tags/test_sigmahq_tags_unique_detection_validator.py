# tests/test_sigmahq_tags_unique_detection_validator.py

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.tags import (
    SigmahqTagsUniqueDetectionIssue,
    SigmahqTagsUniqueDetectionValidator,
)


def test_validator_SigmahqTagsUniqueDetection():
    validator = SigmahqTagsUniqueDetectionValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [SigmahqTagsUniqueDetectionIssue([rule])]


def test_validator_SigmahqTagsUniqueDetection_valid():
    validator = SigmahqTagsUniqueDetectionValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []
