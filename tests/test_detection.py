from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.detection import (
    SigmahqCategoryEventIdIssue,
    SigmahqCategoryEventIdValidator,
    SigmahqCategoryProvidernameIssue,
    SigmahqCategoryProvidernameValidator,
)


def test_validator_SigmahqCategorieEventid():
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
    assert validator.validate(rule) == [SigmahqCategoryEventIdIssue(rule)]


def test_validator_SigmahqCategorieEventid_valid():
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


def test_validator_SigmahqCategoryProvidername():
    validator = SigmahqCategoryProvidernameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field: path\\*something
            Provider_Name: Microsoft-Windows-Sysmon
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqCategoryProvidernameIssue(rule)]


def test_validator_SigmahqCategoryProvidername_valid():
    validator = SigmahqCategoryProvidernameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
