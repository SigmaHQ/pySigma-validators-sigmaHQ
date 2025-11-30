from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.logsource import (
    SigmahqSysmonMissingEventidIssue,
    SigmahqSysmonMissingEventidValidator,
)


def test_validator_SigmahqSysmonMissingEventid():
    validator = SigmahqSysmonMissingEventidValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: sysmon
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == [
        SigmahqSysmonMissingEventidIssue([detection_rule])
    ]


def test_validator_SigmahqSysmonMissingEventid_valid():
    validator = SigmahqSysmonMissingEventidValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: sysmon
    detection:
        sel:
            EventID: 255
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqSysmonMissingEventid_other():
    validator = SigmahqSysmonMissingEventidValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: dns
    detection:
        sel:
            EventID: 255
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_mitre_link_with_references_correlation():
    """Test that the validator correctly identifies a Sigma correlation rule with MITRE references."""
    validator = SigmahqSysmonMissingEventidValidator()
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
