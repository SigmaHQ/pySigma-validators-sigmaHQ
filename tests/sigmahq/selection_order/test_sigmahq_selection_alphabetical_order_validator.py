import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.selection_order import SigmahqSelectionAlphabeticalOrderValidator

pytestmark = pytest.mark.sigmahq

test_cases = [
    (
        "Alphabetical order - no issue",
        {
            "title": "Test Rule",
            "description": "Detects test",
            "status": "experimental",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": ["cmd.exe", "powershell.exe", "pwsh.exe"]},
                "condition": "selection",
            },
            "level": "medium",
            "falsepositives": ["Unknown"],
            "author": "Test",
            "date": "2024-01-01",
        },
        [],
    ),
    (
        "Non-alphabetical order - issue",
        {
            "title": "Test Rule",
            "description": "Detects test",
            "status": "experimental",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": ["zombie.exe", "cmd.exe", "powershell.exe"]},
                "condition": "selection",
            },
            "level": "medium",
            "falsepositives": ["Unknown"],
            "author": "Test",
            "date": "2024-01-01",
        },
        ["*zombie.exe", "*cmd.exe", "*powershell.exe"],
    ),
    (
        "Two items not in order - issue",
        {
            "title": "Test Rule",
            "description": "Detects test",
            "status": "experimental",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {"Image|endswith": ["z.exe", "a.exe"]},
                "condition": "selection",
            },
            "level": "medium",
            "falsepositives": ["Unknown"],
            "author": "Test",
            "date": "2024-01-01",
        },
        ["*z.exe", "*a.exe"],
    ),
    (
        "Single item - no issue",
        {
            "title": "Test Rule",
            "description": "Detects test",
            "status": "experimental",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {"selection": {"Image|endswith": "cmd.exe"}, "condition": "selection"},
            "level": "medium",
            "falsepositives": ["Unknown"],
            "author": "Test",
            "date": "2024-01-01",
        },
        [],
    ),
    (
        "Mixed - some alphabetical some not",
        {
            "title": "Test Rule",
            "description": "Detects test",
            "status": "experimental",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection1": {"Image|endswith": ["a.exe", "b.exe", "c.exe"]},
                "selection2": {"Image|contains": ["zombie", "cmd", "powershell"]},
                "condition": "1 of selection*",
            },
            "level": "medium",
            "falsepositives": ["Unknown"],
            "author": "Test",
            "date": "2024-01-01",
        },
        ["*zombie*", "*cmd*", "*powershell*"],
    ),
]


@pytest.mark.parametrize("name,rule_dict,expected_values", test_cases)
def test_sigmahq_selection_alphabetical_order_validator(name, rule_dict, expected_values):
    rule = SigmaRule.from_dict(rule_dict)
    validator = SigmahqSelectionAlphabeticalOrderValidator()
    issues = validator.validate(rule)

    if expected_values:
        assert len(issues) == 1
        assert issues[0].values == expected_values
    else:
        assert len(issues) == 0
