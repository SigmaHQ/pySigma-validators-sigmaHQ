from sigma.rule import SigmaLogSource
from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.filename import (
    SigmahqFilenamePrefixIssue,
    SigmahqFilenamePrefixValidator,
)


def test_validator_SigmahqPrefixFilename():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [
        SigmahqFilenamePrefixIssue(
            [rule],
            "Name.yml",
            SigmaLogSource(category="process_creation", product="windows", service=None),
            "proc_creation_win_",
        )
    ]


def test_validator_SigmahqPrefixFilename_valid():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_SigmahqPrefixFilename_product():
    validator = SigmahqFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_name_product_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [
        SigmahqFilenamePrefixIssue(
            [rule],
            "rule_for_macos.yml",
            SigmaLogSource(category=None, product="macos", service="test"),
            "macos_",
        )
    ]
