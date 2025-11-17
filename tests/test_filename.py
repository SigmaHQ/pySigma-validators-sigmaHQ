from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from sigma.validators.sigmahq.filename import (
    SigmahqFilenameConventionIssue,
    SigmahqFilenameConventionValidator,
    SigmahqFilenamePrefixIssue,
    SigmahqFilenamePrefixValidator,
    SigmahqCorrelationFilenamePrefixIssue,
    SigmahqCorrelationFilenamePrefixValidator,
)


def test_validator_SigmahqFilename():
    validator = SigmahqFilenameConventionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqFilenameConventionIssue([rule], "Name.yml")]


def test_validator_SigmahqFilename_valid():
    validator = SigmahqFilenameConventionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


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


def test_validator_SigmahqCorrelationFilename():
    """Test that correlation files without correlation_ prefix fail validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/correlation/invalid_prefix_name.yml"]
    )
    rule = sigma_collection[0]
    assert isinstance(rule, SigmaCorrelationRule)
    assert validator.validate(rule) == [
        SigmahqCorrelationFilenamePrefixIssue([rule], "invalid_prefix_name.yml")
    ]


def test_validator_SigmahqCorrelationFilename_valid():
    """Test that correlation files with correlation_ prefix pass validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/correlation/correlation_valid_filename.yml"]
    )
    rule = sigma_collection[0]
    assert isinstance(rule, SigmaCorrelationRule)
    assert validator.validate(rule) == []


def test_validator_SigmahqCorrelationFilename_combined_valid():
    """Test that combined format files with correlation_ prefix pass validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/correlation/correlation_combined_format.yml"]
    )

    # Find the correlation rule in the combined file
    correlation_rule = None
    for rule in sigma_collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            correlation_rule = rule
            break

    assert correlation_rule is not None
    assert validator.validate(correlation_rule) == []
