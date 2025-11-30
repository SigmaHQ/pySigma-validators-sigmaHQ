from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.references import (
    SigmahqMitreLinkIssue,
    SigmahqMitreLinkValidator,
)


def test_validator_mitre_link_with_references():
    """Test that the validator correctly identifies a Sigma rule with MITRE references."""
    validator = SigmahqMitreLinkValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test
description: Test
status: stable
references:
    - https://attack.mitre.org/techniques/T0001/
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqMitreLinkIssue([detection_rule], "https://attack.mitre.org/techniques/T0001/")
    ]


def test_validator_mitre_link_without_references():
    """Test that the validator passes a Sigma rule without MITRE references."""
    validator = SigmahqMitreLinkValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test
description: Test
status: stable
references:
    - http://some-blog.org
tags:
    - attack.t1588.007
logsource:
    category: test
detection:
    sel:
        candle|exists: true
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_correlation_rules_temporal():
    """Test that the validator passes a Sigma correlation rule with temporal correlation."""
    validator = SigmahqMitreLinkValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
"""
    )
    assert validator.validate(correlation_rule) == []


def test_validator_mitre_link_with_references_correlation():
    """Test that the validator correctly identifies a Sigma correlation rule with MITRE references."""
    validator = SigmahqMitreLinkValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
correlation:
    type: temporal
    rules:
        - 5638f7c0-ac70-491d-8465-2a65075e0d86
    timespan: 5m
    group-by:
        - ComputerName
references:
    - https://attack.mitre.org/techniques/T0001/
"""
    )
    assert validator.validate(correlation_rule) == [
        SigmahqMitreLinkIssue([correlation_rule], "https://attack.mitre.org/techniques/T0001/")
    ]
