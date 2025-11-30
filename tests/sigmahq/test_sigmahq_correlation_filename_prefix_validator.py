from sigma.correlations import SigmaCorrelationRule
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.filename import (
    SigmahqCorrelationFilenamePrefixIssue,
    SigmahqCorrelationFilenamePrefixValidator,
)


def test_validator_SigmahqCorrelationFilename():
    """Test that correlation files without correlation_ prefix fail validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        [
            "tests/files/rules-correlations/invalid_prefix_name.yml",
            "tests/files/rule_filename_valid/proc_creation_win_svchost_accepteula.yml",
        ]
    )
    for rule in sigma_collection:
        if isinstance(rule, SigmaCorrelationRule):
            corelation_rule = rule
    assert validator.validate(corelation_rule) == [
        SigmahqCorrelationFilenamePrefixIssue([corelation_rule], "invalid_prefix_name.yml")
    ]


def test_validator_SigmahqCorrelationFilename_valid():
    """Test that correlation files with correlation_ prefix pass validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        [
            "tests/files/rules-correlations/correlation_valid_filename.yml",
            "tests/files/rule_filename_valid/proc_creation_win_svchost_accepteula.yml",
        ]
    )
    for rule in sigma_collection:
        if isinstance(rule, SigmaCorrelationRule):
            corelation_rule = rule
    assert validator.validate(corelation_rule) == []


def test_validator_SigmahqCorrelationFilename_combined_valid():
    """Test that combined format files with correlation_ prefix pass validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/files/rules-correlations/correlation_combined_format.yml"]
    )

    # Find the correlation rule in the combined file
    correlation_rule = None
    for rule in sigma_collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            correlation_rule = rule
            break

    assert correlation_rule is not None
    assert validator.validate(correlation_rule) == []


def test_validator_SigmahqDetectionFilename():
    """Test that detection files without correlation_ prefix pass validation (detection rules should not be validated by this validator)"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        [
            "tests/files/rule_filename_valid/proc_creation_win_svchost_accepteula.yml",
        ]
    )

    # Find the detection rule
    detection_rule = None
    for rule in sigma_collection:
        if not isinstance(rule, SigmaCorrelationRule):
            detection_rule = rule
            break

    assert detection_rule is not None
    # Detection rules should not trigger this validator, so validation should return empty list
    assert validator.validate(detection_rule) == []
