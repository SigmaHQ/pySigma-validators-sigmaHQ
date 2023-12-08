from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource

from sigma.validators.sigmahq.logsource import (
    SigmahqLogsourceValidIssue,
    SigmahqLogsourceValidValidator,
)


def test_validator_SigmahqSpaceFieldname():
    validator = SigmahqLogsourceValidValidator()
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
        SigmahqLogsourceValidIssue(rule, SigmaLogSource(category="test"))
    ]


def test_validator_SigmahqSpaceFieldname_valid():
    validator = SigmahqLogsourceValidValidator()
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
