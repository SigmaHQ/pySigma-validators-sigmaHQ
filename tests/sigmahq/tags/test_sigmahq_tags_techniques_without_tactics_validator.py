# tests/test_sigmahq_tags_techniques_without_tactics_validator.py

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.tags import (
    SigmahqTagsTechniquesWithoutTacticsIssue,
    SigmahqTagsTechniquesWithoutTacticsValidator,
)


def test_validator_SigmahqTagsTechniquesWithoutTactics():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - attack.t1027.004
    - attack.t1027.005
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )

    assert validator.validate(rule) == [
        SigmahqTagsTechniquesWithoutTacticsIssue(
            [rule],
            techniques=["attack.t1027.004", "attack.t1027.005"],
            missing_tactic="attack.defense-evasion",
        )
    ]


def test_validator_SigmahqTagsTechniquesWithoutTactics_valid():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - attack.t1027.004
    - attack.t1027.005
    - attack.defense-evasion
    - attack.t1003
    - attack.credential-access
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsInvalidTechnique():
    """Test that invalid MITRE technique codes don't cause KeyError"""
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    # This rule contains an invalid T123456789 technique code
    rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - attack.t123456789
    - tlp.clear
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    # Should not raise KeyError, should return empty list since invalid technique is ignored
    assert validator.validate(rule) == []
