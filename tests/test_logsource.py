from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource

from sigma.validators.sigmahq.check_logsource import (
    SigmahqLogsourceUnknownIssue,
    SigmahqLogsourceUnknownValidator,
    SigmahqSysmonMissingEventidIssue,
    SigmahqSysmonMissingEventidValidator,
)


def test_validator_SigmahqLogsourceKnown():
    validator = SigmahqLogsourceUnknownValidator()
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
    assert validator.validate(rule) == [
        SigmahqLogsourceUnknownIssue([rule], SigmaLogSource(category="test"))
    ]


def test_validator_SigmahqLogsourceKnown_valid():
    validator = SigmahqLogsourceUnknownValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
       product: windows
       service: terminalservices-localsessionmanager
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


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
