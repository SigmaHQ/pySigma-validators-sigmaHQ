# tests/sigmahq/test_sigmahq_tags_unique_tlp_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.tags import (
    SigmahqTagsUniqueTlpIssue,
    SigmahqTagsUniqueTlpValidator,
)

#
# Detection Rule Tests
#


def test_validator_SigmahqTagsUniqueTlp():
    validator = SigmahqTagsUniqueTlpValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - tlp.clear
    - tlp.amber
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [SigmahqTagsUniqueTlpIssue([detection_rule])]


def test_validator_SigmahqTagsUniqueTlp_valid():
    validator = SigmahqTagsUniqueTlpValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - tlp.amber
    - attack.t1234
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


def test_validator_SigmahqTagsUniqueTlp_correlation():
    validator = SigmahqTagsUniqueTlpValidator()
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


def test_validator_SigmahqTagsUniqueTlp_correlation_multiple_tlps():
    validator = SigmahqTagsUniqueTlpValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
tags:
    - tlp.clear
    - tlp.amber
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
    assert validator.validate(correlation_rule) == [SigmahqTagsUniqueTlpIssue([correlation_rule])]
