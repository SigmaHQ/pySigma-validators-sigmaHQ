from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFalsepositivesCapitalIssue,
    SigmahqFalsepositivesCapitalValidator,
)


def test_validator_SigmahqFalsepositivesCapital():
    validator = SigmahqFalsepositivesCapitalValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - unknown
        - possible
    """
    )
    assert validator.validate(rule) == [
        SigmahqFalsepositivesCapitalIssue([rule], "unknown"),
        SigmahqFalsepositivesCapitalIssue([rule], "possible"),
    ]


def test_validator_SigmahqFalsepositivesCapital_valid():
    validator = SigmahqFalsepositivesCapitalValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Unknown
        - Possible
    """
    )
    assert validator.validate(rule) == []
