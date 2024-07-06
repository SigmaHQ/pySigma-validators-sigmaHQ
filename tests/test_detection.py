from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.detection import (
    SigmahqCategorieEventidIssue,
    SigmahqCategorieEventidValidator,
)


def test_validator_SigmahqSpaceFieldname():
    validator = SigmahqCategorieEventidValidator()
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
    assert validator.validate(rule) == [SigmahqCategorieEventidIssue(rule)]


def test_validator_SigmahqSpaceFieldname_valid():
    validator = SigmahqCategorieEventidValidator()
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
