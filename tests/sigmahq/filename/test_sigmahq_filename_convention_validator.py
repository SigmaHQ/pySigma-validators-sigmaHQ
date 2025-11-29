from sigma.collection import SigmaCollection
from sigma.validators.sigmahq.filename import (
    SigmahqFilenameConventionIssue,
    SigmahqFilenameConventionValidator,
)


def test_validator_SigmahqFilename():
    validator = SigmahqFilenameConventionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_errors"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqFilenameConventionIssue([rule], "Name.yml")]


def test_validator_SigmahqFilename_valid():
    validator = SigmahqFilenameConventionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rule_filename_valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []
