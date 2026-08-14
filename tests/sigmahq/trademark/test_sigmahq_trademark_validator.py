from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.trademark import (
    SigmahqTrademarkIssue,
    SigmahqTrademarkValidator,
)


def test_validator_SigmahqTrademark_valid():
    validator = SigmahqTrademarkValidator()
    rule = SigmaRule.from_yaml(
        """
title: Detects suspicious process execution
status: test
logsource:
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'malicious'
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTrademark_mitre_att_ck():
    validator = SigmahqTrademarkValidator()
    rule = SigmaRule.from_yaml(
        """
title: Detects MITRE ATT&CK technique
status: test
logsource:
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'malicious'
    condition: sel
"""
    )
    issues = validator.validate(rule)
    assert len(issues) == 2
    assert isinstance(issues[0], SigmahqTrademarkIssue)
    assert issues[0].trademark == "MITRE ATT&CK"
    assert isinstance(issues[1], SigmahqTrademarkIssue)
    assert issues[1].trademark == "ATT&CK"


def test_validator_SigmahqTrademark_att_ck_only():
    validator = SigmahqTrademarkValidator()
    rule = SigmaRule.from_yaml(
        """
title: Uses ATT&CK framework for analysis
status: test
logsource:
    category: process_creation
detection:
    sel:
        CommandLine|contains: 'malicious'
    condition: sel
"""
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqTrademarkIssue)
    assert issues[0].trademark == "ATT&CK"


def test_validator_SigmahqTrademark_valid_correlation():
    validator = SigmahqTrademarkValidator()
    rule = SigmaCorrelationRule.from_yaml(
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
    assert validator.validate(rule) == []
