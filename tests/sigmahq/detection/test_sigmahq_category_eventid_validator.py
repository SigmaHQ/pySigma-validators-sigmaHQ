from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqCategoryEventIdIssue,
    SigmahqCategoryEventIdValidator,
)


def test_validator_SigmahqCategoryEventId():
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: ps_module
detection:
    sel:
        field: path\\*something
        EventID: 4103
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqCategoryEventIdIssue([rule])]


def test_validator_SigmahqCategoryEventId_valid():
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: ps_module
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqCategoryEventId_other():
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []
