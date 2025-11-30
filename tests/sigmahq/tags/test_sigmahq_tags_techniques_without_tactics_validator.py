# tests/sigmahq/test_sigmahq_tags_techniques_without_tactics_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.tags import (
    SigmahqTagsTechniquesWithoutTacticsIssue,
    SigmahqTagsTechniquesWithoutTacticsValidator,
)


def test_validator_SigmahqTagsTechniquesWithoutTactics():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    detection_rule = SigmaRule.from_yaml(
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

    assert validator.validate(detection_rule) == [
        SigmahqTagsTechniquesWithoutTacticsIssue(
            [detection_rule],
            techniques=["attack.t1027.004", "attack.t1027.005"],
            missing_tactic="attack.defense-evasion",
        )
    ]


def test_validator_SigmahqTagsTechniquesWithoutTactics_valid():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: test
status: unsupported
tags:
    - attack.defense-evasion
    - attack.t1027.004
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqTagsTechniquesWithoutTactics_correlation():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
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
    assert validator.validate(correlation_rule) == []


def test_validator_SigmahqTagsTechniquesWithoutTactics_correlation_with_tactic():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: test correlation
id: 0e95725d-7320-415d-80f7-004da920fc11
tags:
    - attack.defense-evasion
    - attack.t1027.004
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
    assert validator.validate(correlation_rule) == []
