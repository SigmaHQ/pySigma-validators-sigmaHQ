from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.detection import (
    SigmahqCategorieEventidIssue,
    SigmahqCategorieEventidValidator,
    SigmahqSigmacIssue,
    SigmahqSigmacValidator,
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


def test_validator_SigmahqSigmac():
    validator = SigmahqSigmacValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        andsigmac:
            field: path\\*something
        condition: andsigmac
    """
    )
    assert validator.validate(rule) == [SigmahqSigmacIssue(rule, "andsigmac")]


def test_validator_SigmahqSigmac_valid():
    validator = SigmahqSigmacValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        sigmac:
            field: path\\*something
        condition: sigmac
    """
    )
    assert validator.validate(rule) == []
