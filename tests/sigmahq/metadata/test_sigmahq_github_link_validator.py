# tests/sigmahq/metadata/test_sigmahq_github_link_validator.py
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
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


# Correlation Rule Tests
def test_validator_SigmahqGithubLink_correlation():
    validator = SigmahqGithubLinkValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/README.md
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
    assert validator.validate(rule) == [
        SigmahqGithubLinkIssue(
            [rule], "https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/README.md"
        )
    ]


def test_validator_SigmahqGithubLink_correlation_valid():
    validator = SigmahqGithubLinkValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/e557b4acd15b24ad5e7923c69a3e73c7a512ed2c/README.md
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
    assert validator.validate(rule) == []
