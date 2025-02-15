from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule
from sigma.modifiers import SigmaRegularExpression

from sigma.validators.sigmahq.field import (
    SigmahqSpaceFieldNameIssue,
    SigmahqSpaceFieldNameValidator,
    SigmahqFieldnameCastIssue,
    SigmahqFieldnameCastValidator,
    SigmahqInvalidFieldnameIssue,
    SigmahqInvalidFieldnameValidator,
    SigmahqInvalidAllModifierIssue,
    SigmahqInvalidAllModifierValidator,
    SigmahqFieldDuplicateValueIssue,
    SigmahqFieldDuplicateValueValidator,
    SigmahqSpaceFieldNameIssue,
    SigmahqSpaceFieldNameValidator,
    SigmahqFieldUserIssue,
    SigmahqFieldUserValidator,
    SigmahqInvalidHashKvIssue,
    SigmahqInvalidHashKvValidator,
)


def test_validator_SigmahqSpaceFieldname():
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
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue(rule, "space name")]


def test_validator_SigmahqSpaceFieldname_valid():
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


def test_validator_SigmahqInvalidAllModifierIssue():
    validator = SigmahqInvalidAllModifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Use All modificator
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|all: 'one'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidAllModifierIssue(rule, "CommandLine")]


def test_validator_SigmahqInvalidAllModifierIssue_valid():
    validator = SigmahqInvalidAllModifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Use All modificator
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|all: 
                - 'one'
                - 'two'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue():
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|all: 
              - 'one'
              - 'two'
              - 'three'
              - 'Two'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqFieldDuplicateValueIssue(rule, "CommandLine", "Two")]


def test_validator_SigmahqFieldDuplicateValueIssue_base64():
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Base64 Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|base64: 
              - 'one'
              - 'two'
              - 'three'
              - 'Two'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_re():
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Re Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: 
              - 'test.*Test'
              - 'test.*test'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_cased():
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Cased Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|cased|contains:
              - ':\\wIndows\\'
              - ':\\wiNdows\\'
              - ':\\winDows\\'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFieldDuplicateValueIssue_casesensitive():
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Re Duplicate Case Sensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|re: 
              - 'one'
              - 'One'
              - 'two'
              - 'three'
              - 'Two'
              - 'One'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqFieldDuplicateValueIssue(
            rule, "CommandLine", str(SigmaRegularExpression(regexp="One", flags=set()))
        )
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_valid():
    validator = SigmahqFieldDuplicateValueValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Cased Duplicate 
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            CommandLine|contains:
              - 'azertyy'
              - 'qwerty'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqSpaceFieldNameValidator():
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
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue(rule, "Command Line")]


def test_validator_SigmahqSpaceFieldNameValidator_valid():
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


def test_validator_SigmahqFieldUserValidator():
    validator = SigmahqFieldUserValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            UserName: 'AUTORITE NT'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqFieldUserIssue(rule, "UserName", "AUTORITE NT")]


def test_validator_SigmahqInvalidHashKvValidator_invalidhashname():
    validator = SigmahqInvalidHashKvValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Sysmon Hash Validation
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Hashes|contains:
                - 'MD5=4fae81eb7018069e75a087c38af783df'
                - 'SHA512=123456'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue(rule, "SHA512")]


def test_validator_SigmahqInvalidHashKvValidator_invalidhashdata():
    validator = SigmahqInvalidHashKvValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Sysmon Hash Validation
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Hashes|contains:
                - 'MD5=4fae81eb7018069e75a087c38af783df'
                - 'SHA256=123456'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue(rule, "123456")]


def test_validator_SigmahqInvalidHashKvValidator_invalidtypo():
    validator = SigmahqInvalidHashKvValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Sysmon Hash Validation
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Hashes|contains: 'azerty'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue(rule, "azerty")]


def test_validator_SigmahqInvalidHashKvValidator_invalidtype():
    validator = SigmahqInvalidHashKvValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Sysmon Hash Validation
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Hashes: 1234
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue(rule, 1234)]


def test_validator_SigmahqInvalidHashKvValidator_valid():
    validator = SigmahqInvalidHashKvValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Sysmon Hash Validation
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Hashes|contains: 'MD5=4fae81eb7018069e75a087c38af783df'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
