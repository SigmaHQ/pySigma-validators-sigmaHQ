from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.identifier import (
    SigmahqIdentifierExistenceIssue,
    SigmahqIdentifierExistenceValidator,
    SigmahqIdentifierIssue,
    SigmahqIdentifierValidator,
)


def test_validator_identifier_valid_uuid():
    validator = SigmahqIdentifierValidator()
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


def test_validator_identifier_invalid_uuid():
    validator = SigmahqIdentifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    id: 12345678-1234-5678-1234-567812345678
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
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqIdentifierIssue)
    assert issues[0].id == "12345678-1234-5678-1234-567812345678"


def test_validator_identifier_missing():
    validator = SigmahqIdentifierExistenceValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
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
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqIdentifierExistenceIssue)


def test_validator_identifier_with_correlation_valid():
    validator = SigmahqIdentifierValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
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
    assert validator.validate(rule) == []


def test_validator_identifier_with_correlation_invalid():
    validator = SigmahqIdentifierValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
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
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqIdentifierIssue)
    assert issues[0].id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_validator_identifier_none_id():
    validator = SigmahqIdentifierValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
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


def test_validator_identifier_existence_correlation_no_id():
    """Correlation rules don't require an id (optional per spec)."""
    validator = SigmahqIdentifierExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    status: test
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
