import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.field import (
    SigmahqInvalidHashKvIssue,
    SigmahqInvalidHashKvValidator,
)


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


def test_validator_SigmahqInvalidHashKvValidator_invalidimphash():
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
                - 'IMPHASH=123456'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqInvalidHashKvIssue([rule], "123456")]


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
