from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

from sigma.validators.sigmahq.field import (
    SigmahqRedundantFieldIssue,
    SigmahqRedundantFieldValidator,
)


def test_validator_SigmahqRedundantField():
    """Test that redundant fields are detected"""
    validator = SigmahqRedundantFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Field Already in the Logsource
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            EventType: SetValue
            TargetObject|contains: 'SigmaHQ'
            Details|startswith: 'rules'
        condition: selection
    """
    )
    assert validator.validate(rule) == [SigmahqRedundantFieldIssue([rule], "EventType")]


def test_validator_SigmahqRedundantField_valid():
    """Test that non-redundant fields are accepted"""
    validator = SigmahqRedundantFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Field Already in the Logsource
    status: test
    logsource:
        category: registry_set
        product: windows
    detection:
        selection:
            TargetObject|contains: 'SigmaHQ'
            Details|startswith: 'rules'
        condition: selection
    """
    )
    assert validator.validate(rule) == []
