from uuid import UUID
from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection

from sigma.validators.sigmahq.filename import (
    SigmahqFilenameIssue,
    SigmahqFilenameValidator,
    SigmahqFilenamePrefixIssue,
    SigmahqFilenamePrefixValidator,
)

from sigma.validators.sigmahq.metadata import (
    SigmahqTitleLengthIssue,
    SigmahqTitleLengthValidator,
    SigmahqStatusExistenceIssue,
    SigmahqStatusExistenceValidator,
    SigmahqStatusUnsupportedIssue,
    SigmahqStatusUnsupportedValidator,
    SigmahqStatusDeprecatedIssue,
    SigmahqStatusDeprecatedValidator,
    SigmahqDateExistenceIssue,
    SigmahqDateExistenceValidator,
    SigmahqDescriptionExistenceIssue,
    SigmahqDescriptionExistenceValidator,
    SigmahqDescriptionLengthIssue,
    SigmahqDescriptionLengthValidator,
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
)


def test_validator_SigmahqFilename():
    validator = SigmahqFilenameValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/rule_filename_errors"]
    )
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqFilenameIssue([rule], "Name.yml")]


def test_validator_SigmahqPrefixFilename():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/rule_filename_errors"]
    )
    rule = sigma_collection[0]
    assert validator.validate(rule) == [
        SigmahqFilenamePrefixIssue(
            [rule], "Name.yml", SigmaLogSource("process_creation", "windows", None)
        )
    ]


def test_validator_SigmahqTitleLength():
    validator = SigmahqTitleLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: ThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleThisIsAVeryLongTitleTitleThisIsAVeryLongTitle
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqTitleLengthIssue([rule])]


def test_validator_SigmahqStatusUnsupported():
    validator = SigmahqStatusUnsupportedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusUnsupportedIssue([rule])]


def test_validator_SigmahqStatusDeprecated():
    validator = SigmahqStatusDeprecatedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: deprecated
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusDeprecatedIssue([rule])]


def test_validator_SigmahqDateExistence():
    validator = SigmahqDateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDateExistenceIssue([rule])]


def test_validator_SigmahqStatusExistence():
    validator = SigmahqStatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusExistenceIssue([rule])]


def test_validator_SigmahqDescriptionExistence():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDescriptionExistenceIssue([rule])]


def test_validator_SigmahqDescriptionLength():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDescriptionLengthIssue([rule])]


def test_validator_SigmahqLevelExistence():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLevelExistenceIssue([rule])]
