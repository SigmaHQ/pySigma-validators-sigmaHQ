# tests/test_tags.py

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection

from sigma.validators.sigmahq.tags import (
    SigmahqTagsDetectionIssue,
    SigmahqTagsDetectionValidator,
    SigmahqTagsTlpIssue,
    SigmahqTagsTlpValidator,
    SigmahqTagsUniqueDetectionIssue,
    SigmahqTagsUniqueDetectionValidator,
    SigmahqTagsUniqueTlpIssue,
    SigmahqTagsUniqueTlpValidator,
    SigmahqTagsTechniquesWithoutTacticsIssue,
    SigmahqTagsTechniquesWithoutTacticsValidator,
)


def test_validator_SigmahqTagsDetection():
    validator = SigmahqTagsDetectionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-emerging-threats/invalid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == [SigmahqTagsDetectionIssue([rule], tag="emerging-threats")]


def test_validator_SigmahqTagsDetection_valid():
    validator = SigmahqTagsDetectionValidator()
    sigma_collection = SigmaCollection.load_ruleset(["tests/files/rules-emerging-threats/valid"])
    rule = sigma_collection[0]
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsDetection_no_folders():
    validator = SigmahqTagsDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - detection.threat-hunting
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsUniqueDetection():
    validator = SigmahqTagsUniqueDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - detection.dfir
        - detection.threat-hunting
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqTagsUniqueDetectionIssue([rule])]


def test_validator_SigmahqTagsUniqueDetection_valid():
    validator = SigmahqTagsUniqueDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - detection.dfir
        - tlp.clean
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsTlp():
    validator = SigmahqTagsTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.red
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqTagsTlpIssue([rule], tlp="red")]


def test_validator_SigmahqTagsTlp_valid():
    validator = SigmahqTagsTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.clear
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsUniqueTlp():
    validator = SigmahqTagsUniqueTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.clear
        - tlp.amber
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqTagsUniqueTlpIssue([rule])]


def test_validator_SigmahqTagsUniqueTlp_valid():
    validator = SigmahqTagsUniqueTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.amber
        - attack.t1234
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsNoTags():
    # Test for no tags at all
    validators = [SigmahqTagsUniqueDetectionValidator(), SigmahqTagsUniqueTlpValidator()]
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
    for validator in validators:
        assert validator.validate(rule) == []


def test_validator_SigmahqTagsNoTlp():
    # Test for no TLP tags
    validator = SigmahqTagsUniqueTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - detection.dfir
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsNoDetection():
    # Test for no detection tags
    validator = SigmahqTagsUniqueDetectionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.clear
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsTechniquesWithoutTactics():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - attack.t1027.004
        - attack.t1027.005
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )

    assert validator.validate(rule) == [
        SigmahqTagsTechniquesWithoutTacticsIssue(
            [rule],
            techniques=["attack.t1027.004", "attack.t1027.005"],
            missing_tactic="attack.defense-evasion",
        )
    ]


def test_validator_SigmahqTagsTechniquesWithoutTactics_valid():
    validator = SigmahqTagsTechniquesWithoutTacticsValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - attack.t1027.004
        - attack.t1027.005
        - attack.defense-evasion
        - attack.t1003
        - attack.credential-access
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
