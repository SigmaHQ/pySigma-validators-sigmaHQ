from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.metadata import (
    SigmahqLicenseIssue,
    SigmahqLicenseValidator,
)


def test_validator_SigmahqLicense_valid_string():
    validator = SigmahqLicenseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
license: MIT
detection:
    sel:
        field: path
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqLicense_valid_none():
    validator = SigmahqLicenseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
detection:
    sel:
        field: path
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqLicense_invalid_list():
    validator = SigmahqLicenseValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    category: test
license:
    - MIT
    - Apache-2.0
detection:
    sel:
        field: path
    condition: sel
""",
        collect_errors=True,
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqLicenseIssue)


def test_validator_SigmahqLicense_invalid_correlation():
    validator = SigmahqLicenseValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Test Correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
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
    assert validator.validate(rule) == []
