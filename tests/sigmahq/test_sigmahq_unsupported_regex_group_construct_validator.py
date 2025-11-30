from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.sigmahq.detection import (
    SigmahqUnsupportedRegexGroupConstructIssue,
    SigmahqUnsupportedRegexGroupConstructValidator,
)


def test_validator_SigmahqUnsupportedRegexGroupConstruct():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field|re: 'A(?=B)'
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([detection_rule], "A(?=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_valid():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field|re: 'a\\w+b'
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == []


def test_validator_SigmahqUnsupportedRegexGroupConstruct_lookbehind():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field|re: 'A(?<!B)'
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([detection_rule], "A(?<!B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_negative_lookahead():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field|re: 'A(?!B)'
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([detection_rule], "A(?!B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_positive_lookbehind():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field|re: 'A(?<=B)'
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([detection_rule], "A(?<=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_complex_regex():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    detection_rule = SigmaRule.from_yaml(
        """
title: A Space Field Name
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field|re: '(?P<name>\\w+)(?=\\s+\\w+)'
    condition: sel
"""
    )
    assert validator.validate(detection_rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([detection_rule], "(?P<name>\\w+)(?=\\s+\\w+)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_correlation_single_dot():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    correlation_rule = SigmaCorrelationRule.from_yaml(
        """
title: .
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
    assert validator.validate(correlation_rule) == []
