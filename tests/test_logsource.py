from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource

from sigma.validators.sigmahq.logsource import (
    SigmahqLogsourceKnownIssue,
    SigmahqLogsourceKnownValidator,
    SigmahqLogsourceCoherentIssue,
    SigmahqLogsourceCoherentValidator,
)


def test_validator_SigmahqLogsourceKnown():
    validator = SigmahqLogsourceKnownValidator()
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
        SigmahqLogsourceKnownIssue(rule, SigmaLogSource(category="test"))
    ]


def test_validator_SigmahqLogsourceKnown_valid():
    validator = SigmahqLogsourceKnownValidator()
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


def test_validator_SigmahqLogsourceCoherent_service_alone():
    validator = SigmahqLogsourceCoherentValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        service: test
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqLogsourceCoherentIssue(rule, SigmaLogSource(service="test"))
    ]


def test_validator_SigmahqLogsourceCoherent_valid():
    validator = SigmahqLogsourceCoherentValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: test
        service: test
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
