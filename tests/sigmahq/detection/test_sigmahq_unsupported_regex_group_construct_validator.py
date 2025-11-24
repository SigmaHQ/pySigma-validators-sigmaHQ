import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqUnsupportedRegexGroupConstructIssue,
    SigmahqUnsupportedRegexGroupConstructValidator,
)


def test_validator_SigmahqUnsupportedRegexGroupConstruct():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_valid():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == []


def test_validator_SigmahqUnsupportedRegexGroupConstruct_lookbehind():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?<!B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_negative_lookahead():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?!B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_positive_lookbehind():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?<=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_complex_regex():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
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
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "(?P<name>\\w+)(?=\\s+\\w+)")
    ]
