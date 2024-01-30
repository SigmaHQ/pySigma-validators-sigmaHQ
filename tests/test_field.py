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
    SigmahqInvalidFieldSourceIssue,
    SigmahqInvalidFieldSourceValidator,
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


def test_validator_SigmahqSpaceFieldname_valid():
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
            space_name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


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


def test_validator_SigmahqFieldnameCast_valid_new_logsource():
    validator = SigmahqFieldnameCastValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: frack
    detection:
        sel:
            MyCommandLine: 'error'
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


def test_validator_SigmahqInvalidFieldname_valid_new_logsource():
    validator = SigmahqInvalidFieldnameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: process_creation
        product: frack
    detection:
        sel:
            MyCommandLines: 'error' # should be MyCommandLine
        condition: sel
    """
    )
    assert validator.validate(rule) == []

def test_validator_SigmahqInvalidFieldSourceIssue():
    validator = SigmahqInvalidFieldSourceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Use Field Source Eventlog
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Source: 'Eventlog'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidFieldSourceIssue(rule)]

def test_validator_SigmahqInvalidFieldSourceIssue_valid():
    validator = SigmahqInvalidFieldSourceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Use Field Source Eventlog
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Source: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == []