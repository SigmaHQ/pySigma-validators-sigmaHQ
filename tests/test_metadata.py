from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.metadata import (
    SigmahqStatusExistenceIssue,
    SigmahqStatusExistenceValidator,
    SigmahqStatusIssue,
    SigmahqStatusValidator,
    SigmahqDateExistenceIssue,
    SigmahqDateExistenceValidator,
    SigmahqDescriptionExistenceIssue,
    SigmahqDescriptionExistenceValidator,
    SigmahqDescriptionLengthIssue,
    SigmahqDescriptionLengthValidator,
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
    SigmahqFalsepositivesCapitalIssue,
    SigmahqFalsepositivesCapitalValidator,
    SigmahqFalsepositivesBannedWordIssue,
    SigmahqFalsepositivesBannedWordValidator,
    SigmahqFalsepositivesTypoWordIssue,
    SigmahqFalsepositivesTypoWordValidator,
    SigmahqLinkInDescriptionIssue,
    SigmahqLinkInDescriptionValidator,
    SigmahqUnknownFieldIssue,
    SigmahqUnknownFieldValidator,
)


def test_validator_SigmahqStatus_Unsupported():
    validator = SigmahqStatusValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusIssue(rule)]


def test_validator_SigmahqStatus_Deprecated():
    validator = SigmahqStatusValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: deprecated
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusIssue(rule)]


def test_validator_SigmahqStatus_valid():
    validator = SigmahqStatusValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqDateExistence():
    validator = SigmahqDateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDateExistenceIssue(rule)]


def test_validator_SigmahqDateExistence_valid():
    validator = SigmahqDateExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: stable
    date: 2023-12-10
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqStatusExistence():
    validator = SigmahqStatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqStatusExistenceIssue(rule)]


def test_validator_SigmahqStatusExistence_valid():
    validator = SigmahqStatusExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqDescriptionExistence():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDescriptionExistenceIssue(rule)]


def test_validator_SigmahqDescriptionExistence_valid():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: a simple description
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqDescriptionLength():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqDescriptionLengthIssue(rule)]


def test_validator_SigmahqDescriptionLength_valid():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: a simple description to test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqLevelExistence():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLevelExistenceIssue(rule)]


def test_validator_SigmahqLevelExistence_valid():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    level: low
    """
    )
    assert validator.validate(rule) == []


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
        SigmahqFalsepositivesCapitalIssue(rule, "unknown"),
        SigmahqFalsepositivesCapitalIssue(rule, "possible"),
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
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue(rule, "Pentest")]


def test_validator_SigmahqFalsepositivesBannedWord_custom():
    validator = SigmahqFalsepositivesBannedWordValidator(word_list=["maybe"])
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
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue(rule, "Maybe")]


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
    assert validator.validate(rule) == [SigmahqFalsepositivesTypoWordIssue(rule, "legitimeate")]


def test_validator_SigmahqFalsepositivesTypoWord_custom():
    validator = SigmahqFalsepositivesTypoWordValidator(word_list=["unkwon"])
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
    assert validator.validate(rule) == [SigmahqFalsepositivesTypoWordIssue(rule, "Unkwon")]


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


def test_validator_SigmahqLinkDescription():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: rule from https://somewhereundertheraimbow
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue(rule, "https://")]


def test_validator_SigmahqLinkDescription():
    validator = SigmahqLinkInDescriptionValidator(word_list=("http://", "https://", "ftp:"))
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: pdf found here ftp://somewhereundertheraimbow
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue(rule, "ftp:")]


def test_validator_SigmahqLinkDescription_valid():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: rule from https://somewhereundertheraimbow
    references:
        - https://somewhereundertheraimbow
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqUnknownField():
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    created: 2024-08-09
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqUnknownFieldIssue(rule, ["created"])]


def test_validator_SigmahqUnknownField_valid():
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    date: 2024-08-09
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []
