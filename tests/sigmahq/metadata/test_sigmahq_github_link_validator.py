from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqGithubLinkIssue,
    SigmahqGithubLinkValidator,
)


def test_validator_SigmahqGithubLink():
    validator = SigmahqGithubLinkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/README.md
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqGithubLinkIssue(
            [rule], "https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/README.md"
        )
    ]


def test_validator_SigmahqGithubLink_valid():
    validator = SigmahqGithubLinkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/e557b4acd15b24ad5e7923c69a3e73c7a512ed2c/README.md
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == []
