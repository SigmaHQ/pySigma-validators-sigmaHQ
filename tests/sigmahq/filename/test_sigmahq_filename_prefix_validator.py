from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.filename import (
    SigmahqFilenamePrefixIssue,
    SigmahqFilenamePrefixValidator,
)
from sigma.rule import SigmaLogSource


def test_validator_SigmahqPrefixFilename():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [
        SigmahqFilenamePrefixIssue(
            [rule],
            "Name.yml",
            SigmaLogSource(category="process_creation", product="windows", service=None),
            "proc_creation_win_",
        )
    ]


def test_validator_SigmahqPrefixFilename_valid():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_SigmahqPrefixFilename_product():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_name_product_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [
        SigmahqFilenamePrefixIssue(
            [rule],
            "rule_for_macos.yml",
            SigmaLogSource(category=None, product="macos", service="test"),
            "macos_",
        )
    ]


def test_validator_SigmahqFilename_with_sigma_rule():
    validator = SigmahqFilenamePrefixValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: Test Rule
id: 12345678-1234-5678-1234-567812345678
status: test
level: medium
description: Test rule for filename validation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqFilename_with_sigma_correlation_rule():
    validator = SigmahqFilenamePrefixValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
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
    fields:
        - field1
        - field2
    """
    )
    # This should return empty list because the validator only validates SigmaRule, not SigmaCorrelationRule
    assert validator.validate(correlation_rule) == []
