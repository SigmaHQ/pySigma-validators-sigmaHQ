from sigma.rule import SigmaRule

from sigma.validators.sigmahq.related import (
    SigmahqRelatedIdentifierIssue,
    SigmahqRelatedIdentifierValidator,
)


def test_validator_related_identifier_valid():
    validator = SigmahqRelatedIdentifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: test
    level: medium
    description: Test rule
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains: 'test'
        condition: selection
    related:
        - type: derived
          id: 12345678-1234-4234-8234-567812345678
        - type: similar
          id: aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa
    """
    )
    assert validator.validate(rule) == []


def test_validator_related_identifier_invalid():
    validator = SigmahqRelatedIdentifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: test
    level: medium
    description: Test rule
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains: 'test'
        condition: selection
    related:
        - type: derived
          id: 12345678-1234-5678-1234-567812345678
    """
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqRelatedIdentifierIssue)
    assert issues[0].id == "12345678-1234-5678-1234-567812345678"


def test_validator_related_identifier_multiple_invalid():
    validator = SigmahqRelatedIdentifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: test
    level: medium
    description: Test rule
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains: 'test'
        condition: selection
    related:
        - type: derived
          id: 12345678-1234-5678-1234-567812345678
        - type: similar
          id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    """
    )
    issues = validator.validate(rule)
    assert len(issues) == 2
    assert isinstance(issues[0], SigmahqRelatedIdentifierIssue)
    assert isinstance(issues[1], SigmahqRelatedIdentifierIssue)
    assert issues[0].id == "12345678-1234-5678-1234-567812345678"
    assert issues[1].id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_validator_related_identifier_none():
    validator = SigmahqRelatedIdentifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: test
    level: medium
    description: Test rule
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains: 'test'
        condition: selection
    """
    )
    assert validator.validate(rule) == []
