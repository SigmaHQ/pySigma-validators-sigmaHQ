from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFalsepositivesBannedWordIssue,
    SigmahqFalsepositivesBannedWordValidator,
)


def test_validator_SigmahqFalsepositivesBannedWord():
    validator = SigmahqFalsepositivesBannedWordValidator()
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
        - Pentest tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Pentest")]


def test_validator_SigmahqFalsepositivesBannedWord_custom():
    validator = SigmahqFalsepositivesBannedWordValidator(word_list=("maybe",))
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
        - Maybe
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Maybe")]


def test_validator_SigmahqFalsepositivesBannedWord_valid():
    validator = SigmahqFalsepositivesBannedWordValidator()
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
        - GPO tools
    """
    )
    assert validator.validate(rule) == []
