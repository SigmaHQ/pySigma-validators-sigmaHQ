from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.metadata import (
    SigmahqStatusExistenceIssue,
    SigmahqStatusExistenceValidator,
    SigmahqStatusUnsupportedIssue,
    SigmahqStatusUnsupportedValidator,
    SigmahqStatusDeprecatedIssue,
    SigmahqStatusDeprecatedValidator,
    SigmahqDateExistenceIssue,
    SigmahqDateExistenceValidator,
    SigmahqDescriptionExistenceIssue,
    SigmahqDescriptionExistenceValidator,
    SigmahqDescriptionLengthIssue,
    SigmahqDescriptionLengthValidator,
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
    SigmahqLegalTrademarkIssue,
    SigmahqLegalTrademarkValidator,
    SigmahqFalsepositivesCapitalIssue,
    SigmahqFalsepositivesCapitalValidator,
    SigmahqFalsepositivesBannedWordIssue,
    SigmahqFalsepositivesBannedWordValidator,
    SigmahqFalsepositivesTypoWordIssue,
    SigmahqFalsepositivesTypoWordValidator,
    SigmahqLinkDescriptionIssue,
    SigmahqLinkDescriptionValidator,
)


def test_validator_SigmahqStatusUnsupported():
    validator = SigmahqStatusUnsupportedValidator()
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
    assert validator.validate(rule) == [SigmahqStatusUnsupportedIssue([rule])]


def test_validator_SigmahqStatusDeprecated():
    validator = SigmahqStatusDeprecatedValidator()
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
    assert validator.validate(rule) == [SigmahqStatusDeprecatedIssue(rule)]


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


def test_validator_SigmahqLegalTrademark():
    validator = SigmahqLegalTrademarkValidator()
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
    """
    )
    assert validator.validate(rule) == [SigmahqLegalTrademarkIssue(rule, "ATT&CK")]


def test_validator_SigmahqLegalTrademark_valid():
    validator = SigmahqLegalTrademarkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: this is a rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
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
    assert validator.validate(rule) == [
        SigmahqFalsepositivesBannedWordIssue(rule, "Pentest")
    ]


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
    assert validator.validate(rule) == [
        SigmahqFalsepositivesTypoWordIssue(rule, "legitimeate")
    ]


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
    validator = SigmahqLinkDescriptionValidator()
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
    assert validator.validate(rule) == [SigmahqLinkDescriptionIssue(rule)]


def test_validator_SigmahqLinkDescription_valid():
    validator = SigmahqLinkDescriptionValidator()
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
