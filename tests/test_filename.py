from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection

from sigma.validators.sigmahq.filename import (
    SigmahqFilenameConventionIssue,
    SigmahqFilenameConventionValidator,
    SigmahqFilenamePrefixIssue,
    SigmahqFilenamePrefixValidator,
)


def test_validator_SigmahqFilename():
    validator = SigmahqFilenameConventionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqFilenameConventionIssue(rule, "Name.yml")]


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
            rule,
            "Name.yml",
            SigmaLogSource("process_creation", "windows", None),
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
            rule,
            "rule_for_macos.yml",
            SigmaLogSource(None, "macos", "test"),
            "macos_",
        )
    ]
