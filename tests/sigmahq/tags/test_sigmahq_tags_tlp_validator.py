# tests/sigmahq/tags/test_sigmahq_tags_tlp_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.tags import (
    SigmahqTagsTlpIssue,
    SigmahqTagsTlpValidator,
)

#
# Detection Rule Tests
#


def test_validator_SigmahqTagsTlp():
    validator = SigmahqTagsTlpValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - tlp.red
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTagsTlpIssue([rule], tlp="red")]


def test_validator_SigmahqTagsTlp_valid():
    validator = SigmahqTagsTlpValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - tlp.clear
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


def test_validator_SigmahqTagsTlp_correlation():
    validator = SigmahqTagsTlpValidator()
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


def test_validator_SigmahqTagsTlp_correlation_red():
    validator = SigmahqTagsTlpValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
tags:
    - tlp.red
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
        SigmahqTagsTlpIssue([correlation_rule], tlp="red")
    ]
