from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.field import (
    SigmahqSpaceFieldnameIssue,
    SigmahqSpaceFieldnameValidator,
    SigmahqFieldnameCastIssue,
    SigmahqFieldnameCastValidator,
    SigmahqInvalidFieldnameIssue,
    SigmahqInvalidFieldnameValidator,
)


def test_validator_SigmahqSpaceFieldname():
    validator = SigmahqSpaceFieldnameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSpaceFieldnameIssue(rule, "space name")]


def test_validator_SigmahqFieldnameCast():
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            commandline: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqFieldnameCastIssue(rule, "commandline")]


def test_validator_SigmahqFieldnameCast_valid():
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqInvalidFieldname():
    validator = SigmahqInvalidFieldnameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: 'error'
            images: '/cmd.exe'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidFieldnameIssue(rule, "images")]


def test_validator_SigmahqInvalidFieldname_valid():
    validator = SigmahqInvalidFieldnameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine: 'error'
            Image: '/cmd.exe'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
