from sigma.rule import SigmaRule
from sigma.validators.sigmahq.tags import (
    SigmahqTagsTlpIssue,
    SigmahqTagsTlpValidator,
)


def test_validator_SigmahqTagsTlp():
    validator = SigmahqTagsTlpValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - tlp.red
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTagsTlpIssue([rule], tlp="red")]


def test_validator_SigmahqTagsTlp_valid():
    validator = SigmahqTagsTlpValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - tlp.clear
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []
