from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.field import (
    SigmahqFieldUserIssue,
    SigmahqFieldUserValidator,
)


def test_validator_SigmahqFieldUserValidator_valid():
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
            UserName: 'root'
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
