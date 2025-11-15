from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

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
    SigmahqFieldUserIssue,
    SigmahqFieldUserValidator,
    SigmahqInvalidHashKvIssue,
    SigmahqInvalidHashKvValidator,
    SigmahqRedundantFieldIssue,
    SigmahqRedundantFieldValidator,
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


def test_validator_SigmahqFieldnameCast():
    """Test that field name casting errors are detected"""
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
    assert validator.validate(rule) == [SigmahqFieldnameCastIssue([rule], "commandline")]


def test_validator_SigmahqFieldnameCast_valid():
    """Test that valid field name casting is accepted"""
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
    """Test that new log sources with custom field names are accepted"""
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
    """Test that invalid field names are detected"""
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
    assert validator.validate(rule) == [SigmahqInvalidFieldnameIssue([rule], "images")]


def test_validator_SigmahqInvalidFieldname_valid():
    """Test that valid field names are accepted"""
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
    """Test that new log sources with custom field names are accepted"""
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
    """Test that all modifier with single value is detected"""
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
    assert validator.validate(rule) == [SigmahqInvalidAllModifierIssue([rule], "CommandLine")]


def test_validator_SigmahqInvalidAllModifierIssue_valid():
    """Test that all modifier with multiple values is accepted"""
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
    """Test that duplicate case insensitive values are detected"""
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
    assert validator.validate(rule) == [
        SigmahqFieldDuplicateValueIssue([rule], "CommandLine", "Two")
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_base64():
    """Test that base64 modifier doesn't trigger duplicate detection"""
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
    """Test that regex modifier doesn't trigger duplicate detection"""
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
    """Test that cased modifier doesn't trigger duplicate detection"""
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
    """Test that case sensitive duplicates are detected"""
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
            [rule], "CommandLine", str(SigmaRegularExpression(regexp="One", flags=set()))
        )
    ]


def test_validator_SigmahqFieldDuplicateValueIssue_valid():
    """Test that valid non-duplicate values are accepted"""
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


def test_validator_SigmahqFieldUserValidator():
    """Test that localized user names are detected"""
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
    assert validator.validate(rule) == [SigmahqFieldUserIssue([rule], "UserName", "AUTORITE NT")]


def test_validator_SigmahqInvalidHashKvValidator_invalidhashname():
    """Test that invalid hash names are detected"""
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
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue([rule], "SHA512")]


def test_validator_SigmahqInvalidHashKvValidator_invalidhashdata():
    """Test that invalid hash data is detected"""
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
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue([rule], "123456")]


def test_validator_SigmahqInvalidHashKvValidator_invalidtypo():
    """Test that invalid hash format is detected"""
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
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue([rule], "azerty")]


def test_validator_SigmahqInvalidHashKvValidator_invalidtype():
    """Test that invalid hash value type is detected"""
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
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue([rule], 1234)]


def test_validator_SigmahqInvalidHashKvValidator_valid_md5():
    """Test that valid MD5 hash is accepted"""
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


def test_validator_SigmahqRedundantField():
    """Test that redundant fields are detected"""
    validator = SigmahqRedundantFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Field Already in the Logsource
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            EventType: SetValue
            TargetObject|contains: 'SigmaHQ'
            Details|startswith: 'rules'
        condition: selection
    """
    )
    assert validator.validate(rule) == [SigmahqRedundantFieldIssue([rule], "EventType")]


def test_validator_SigmahqRedundantField_valid():
    """Test that non-redundant fields are accepted"""
    validator = SigmahqRedundantFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Field Already in the Logsource
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            TargetObject|contains: 'SigmaHQ'
            Details|startswith: 'rules'
        condition: selection
    """
    )
    assert validator.validate(rule) == []
