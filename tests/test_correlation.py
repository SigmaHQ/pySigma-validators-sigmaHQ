
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.correlation import (
    SigmahqCorrelationRulesMinimumIssue,
    SigmahqCorrelationRulesMinimumValidator,
    SigmahqCorrelationGroupByExistenceIssue,
    SigmahqCorrelationGroupByExistenceValidator,
)
from sigma.validators.sigmahq.metadata import (
    SigmahqStatusExistenceIssue,
    SigmahqStatusExistenceValidator,
    SigmahqLevelExistenceIssue,
    SigmahqLevelExistenceValidator,
    SigmahqAuthorExistenceIssue,
    SigmahqAuthorExistenceValidator,
    SigmahqDateExistenceIssue,
    SigmahqDateExistenceValidator,
    SigmahqDescriptionExistenceIssue,
    SigmahqDescriptionExistenceValidator,
    SigmahqDescriptionLengthIssue,
    SigmahqDescriptionLengthValidator,
)


# Tests for Rules Minimum
def test_validator_SigmahqCorrelationRulesMinimum_temporal():
    validator = SigmahqCorrelationRulesMinimumValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    correlation:
        type: temporal
        rules:
            - 5638f7c0-ac70-491d-8465-2a65075e0d86
        timespan: 5m
        group-by:
            - ComputerName
    """
    )
    assert validator.validate(rule) == [SigmahqCorrelationRulesMinimumIssue([rule])]


def test_validator_SigmahqCorrelationRulesMinimum_temporal_valid():
    validator = SigmahqCorrelationRulesMinimumValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    correlation:
        type: temporal
        rules:
            - recon_cmd_a
            - recon_cmd_b
        timespan: 5m
        group-by:
            - ComputerName
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqCorrelationRulesMinimum_temporal_ordered():
    validator = SigmahqCorrelationRulesMinimumValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    correlation:
        type: temporal_ordered
        rules:
            - 5638f7c0-ac70-491d-8465-2a65075e0d86
        timespan: 5m
        group-by:
            - ComputerName
    """
    )
    assert validator.validate(rule) == [SigmahqCorrelationRulesMinimumIssue([rule])]


def test_validator_SigmahqCorrelationRulesMinimum_event_count_valid():
    validator = SigmahqCorrelationRulesMinimumValidator()
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


# Tests for GroupBy Existence
def test_validator_SigmahqCorrelationGroupBy_event_count():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    correlation:
        type: event_count
        rules:
            - 5638f7c0-ac70-491d-8465-2a65075e0d86
        timespan: 1h
        condition:
            gte: 100
    """
    )
    assert validator.validate(rule) == [SigmahqCorrelationGroupByExistenceIssue([rule])]


def test_validator_SigmahqCorrelationGroupBy_temporal():
    validator = SigmahqCorrelationGroupByExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    correlation:
        type: temporal
        rules:
            - recon_cmd_a
            - recon_cmd_b
        timespan: 5m
    """
    )
    assert validator.validate(rule) == [SigmahqCorrelationGroupByExistenceIssue([rule])]


def test_validator_SigmahqCorrelationGroupBy_valid():
    validator = SigmahqCorrelationGroupByExistenceValidator()
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


# Tests for Status Existence
def test_validator_SigmahqStatus_correlation():
    validator = SigmahqStatusExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqStatusExistenceIssue([rule])]


def test_validator_SigmahqStatus_correlation_valid():
    validator = SigmahqStatusExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    status: experimental
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


# Tests for Level Existence
def test_validator_SigmahqLevel_correlation():
    validator = SigmahqLevelExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqLevelExistenceIssue([rule])]


def test_validator_SigmahqLevel_correlation_valid():
    validator = SigmahqLevelExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    level: high
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


# Tests for Author Existence
def test_validator_SigmahqAuthor_correlation():
    validator = SigmahqAuthorExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqAuthorExistenceIssue([rule])]


def test_validator_SigmahqAuthor_correlation_valid():
    validator = SigmahqAuthorExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    author: Test Author
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


# Tests for Date Existence
def test_validator_SigmahqDate_correlation():
    validator = SigmahqDateExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqDateExistenceIssue([rule])]


def test_validator_SigmahqDate_correlation_valid():
    validator = SigmahqDateExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    date: 2024-01-01
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


def test_validator_SigmahqDescription_correlation():
    validator = SigmahqDescriptionExistenceValidator()
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
    assert validator.validate(rule) == [SigmahqDescriptionExistenceIssue([rule])]


def test_validator_SigmahqDescription_correlation_valid():
    validator = SigmahqDescriptionExistenceValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: This is a test correlation rule
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


# Tests for Description Length
def test_validator_SigmahqDescriptionLength_correlation():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: Short
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
    assert validator.validate(rule) == [SigmahqDescriptionLengthIssue([rule])]


def test_validator_SigmahqDescriptionLength_correlation_valid():
    validator = SigmahqDescriptionLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    description: This is a test correlation rule with adequate length
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
