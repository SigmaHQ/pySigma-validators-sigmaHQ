import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.field import (
    SigmahqSpaceFieldNameIssue,
    SigmahqSpaceFieldNameValidator,
)


def test_validator_SigmahqSpaceFieldname():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
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
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "space name")]


def test_validator_SigmahqSpaceFieldname_valid():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
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


def test_validator_SigmahqSpaceFieldNameValidator():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command Line: 'invalid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "Command Line")]


def test_validator_SigmahqSpaceFieldNameValidator_valid():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command_Line: 'valid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqSpaceFieldname():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
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
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "space name")]


def test_validator_SigmahqSpaceFieldname_valid():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
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


def test_validator_SigmahqSpaceFieldNameValidator():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command Line: 'invalid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "Command Line")]


def test_validator_SigmahqSpaceFieldNameValidator_valid():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command_Line: 'valid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
