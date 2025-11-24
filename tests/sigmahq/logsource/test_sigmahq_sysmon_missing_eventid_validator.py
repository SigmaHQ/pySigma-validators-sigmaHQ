import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.logsource import (
    SigmahqSysmonMissingEventidIssue,
    SigmahqSysmonMissingEventidValidator,
)


def test_validator_SigmahqSysmonMissingEventid():
    validator = SigmahqSysmonMissingEventidValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: sysmon
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSysmonMissingEventidIssue([rule])]


def test_validator_SigmahqSysmonMissingEventid_valid():
    validator = SigmahqSysmonMissingEventidValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: sysmon
    detection:
        sel:
            EventID: 255
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqSysmonMissingEventid_other():
    validator = SigmahqSysmonMissingEventidValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: dns
    detection:
        sel:
            EventID: 255
        condition: sel
    """
    )
    assert validator.validate(rule) == []
