from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.field import (
    SigmahqInvalidHashKvIssue,
    SigmahqInvalidHashKvValidator,
)


def test_validator_SigmahqInvalidHashKvValidator_invalidhashname():
    """Test that invalid hash names are detected"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqInvalidHashKvIssue([detection_rule], "SHA512")
    ]


def test_validator_SigmahqInvalidHashKvValidator_invalidimphash():
    """Test that invalid hash names are detected"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqInvalidHashKvIssue([detection_rule], "123456")
    ]


def test_validator_SigmahqInvalidHashKvValidator_invalidhashdata():
    """Test that invalid hash data is detected"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqInvalidHashKvIssue([detection_rule], "123456")
    ]


def test_validator_SigmahqInvalidHashKvValidator_invalidtypo():
    """Test that invalid hash format is detected"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [
        SigmahqInvalidHashKvIssue([detection_rule], "azerty")
    ]


def test_validator_SigmahqInvalidHashKvValidator_invalidtype():
    """Test that invalid hash value type is detected"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == [SigmahqInvalidHashKvIssue([detection_rule], 1234)]


def test_validator_SigmahqInvalidHashKvValidator_valid_md5():
    """Test that valid MD5 hash is accepted"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
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
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqInvalidHashKvValidator_valid_sha256():
    """Test that valid SHA256 hash is accepted"""
    validator = SigmahqInvalidHashKvValidator()
    detection_rule = SigmaRule.from_yaml(
        """
    title: Sysmon Hash Validation
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Hashes|contains: 'SHA256=4fae81eb7018069e75a087c38af783df4fae81eb7018069e75a087c38af783df'
        condition: sel
    """
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqInvalidHashKvValidator_valid_correlation_rule():
    """Test that the validator works with SigmaCorrelationRule"""
    validator = SigmahqInvalidHashKvValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/e557b4acd15b24ad5e7923c69a3e73c7a512ed2c/README.md
    correlation:
        type: event_count
        rules:
            - 5638f7c0-ac70-491d-8465-2a65075e0d86
        timespan: 1h
        group-by:
            - ComputerName
        condition:
            gte: 100
    """
    )
    assert validator.validate(correlation_rule) == []
