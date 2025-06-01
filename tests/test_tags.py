from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection

from sigma.validators.sigmahq.tags import (
    SigmahqTagsDetectionEmergingthreatsIssue,
    SigmahqTagsDetectionEmergingthreatsValidator,
    SigmahqTagsDetectionThreathuntingIssue,
    SigmahqTagsDetectionThreathuntingValidator,
    SigmahqTagsDetectionDfirIssue,
    SigmahqTagsDetectionDfirValidator,
)


def test_validator_SigmahqTagsDetectionEmergingthreats():
    validator = SigmahqTagsDetectionEmergingthreatsValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-emerging-threats/invalid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqTagsDetectionEmergingthreatsIssue([rule])]


def test_validator_SigmahqTagsDetectionEmergingthreats_valid():
    validator = SigmahqTagsDetectionEmergingthreatsValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-emerging-threats/valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsDetectionThreathunting():
    validator = SigmahqTagsDetectionThreathuntingValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-threat-hunting/invalid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqTagsDetectionThreathuntingIssue([rule])]


def test_validator_SigmahqTagsDetectionThreathunting_valid():
    validator = SigmahqTagsDetectionThreathuntingValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-threat-hunting/valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsDetectionDfir():
    validator = SigmahqTagsDetectionDfirValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-dfir/invalid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqTagsDetectionDfirIssue([rule])]


def test_validator_SigmahqTagsDetectionDfir_valid():
    validator = SigmahqTagsDetectionDfirValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-dfir/valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []
