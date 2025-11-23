from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFalsepositivesTypoWordIssue,
    SigmahqFalsepositivesTypoWordValidator,
)


def test_validator_SigmahqFalsepositivesTypoWord():
    validator = SigmahqFalsepositivesTypoWordValidator()
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
        - legitimeate AD tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesTypoWordIssue([rule], "legitimeate")]


def test_validator_SigmahqFalsepositivesTypoWord_custom():
    validator = SigmahqFalsepositivesTypoWordValidator(word_list=("unkwon",))
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
        - Unkwon AD tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesTypoWordIssue([rule], "Unkwon")]


def test_validator_SigmahqFalsepositivesTypoWord_valid():
    validator = SigmahqFalsepositivesTypoWordValidator()
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
        - legitimate AD tools
    """
    )
    assert validator.validate(rule) == []
