from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqLinkInDescriptionIssue,
    SigmahqLinkInDescriptionValidator,
)


def test_validator_SigmahqLinkDescription_https():
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
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue([rule], "https://")]


def test_validator_SigmahqLinkDescription_ftp():
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
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue([rule], "ftp:")]


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
