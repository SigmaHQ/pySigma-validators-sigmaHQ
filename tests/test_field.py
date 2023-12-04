from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.field import (
    SigmahqSpaceFieldnameIssue,
    SigmahqSpaceFieldnameValidator,
)


def test_validator_SigmahqSpaceFieldname():
    validator = SigmahqSpaceFieldnameValidator()
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
        SigmahqSpaceFieldnameIssue([rule], "space name")
    ]
