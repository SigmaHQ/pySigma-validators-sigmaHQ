from uuid import UUID
from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule
from sigma.types import SigmaString
from sigma.collection import SigmaCollection

from sigma.validators.sigmahq.metadata import (
    SigmahqFilenameIssue,
    SigmahqFilenameValidator,
    SigmahqTitleLengthIssue,
    SigmahqTitleLengthValidator,
)


def test_validator_SigmahqFilename():
    validator = SigmahqFilenameValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/rule_filename_errors"]
    )
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqFilenameIssue([rule], "Name.yml")]


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
