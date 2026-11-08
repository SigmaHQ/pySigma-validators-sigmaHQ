import json

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.related import (
    SigmahqRelatedIdExistenceIssue,
    SigmahqRelatedIdExistenceValidator,
)


def _rule_with_related(*related_ids):
    related = "\n".join(f"        - type: derived\n          id: {rid}" for rid in related_ids)
    return SigmaRule.from_yaml(
        f"""
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
    related:
{related}
    """
    )


def _write_rule(path, rule_id, related_ids=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    related = ""
    if related_ids:
        items = "\n".join(f"    - type: derived\n      id: {rid}" for rid in related_ids)
        related = f"related:\n{items}\n"
    path.write_text(
        f"""title: Test
id: {rule_id}
status: test
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: test
    condition: selection
{related}""",
        encoding="utf-8",
    )


def test_validator_related_id_existence_all_present():
    validator = SigmahqRelatedIdExistenceValidator(
        known_ids=[
            "12345678-1234-4234-8234-567812345678",
            "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
        ]
    )
    rule = _rule_with_related(
        "12345678-1234-4234-8234-567812345678",
        "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    )
    assert validator.validate(rule) == []


def test_validator_related_id_existence_missing():
    validator = SigmahqRelatedIdExistenceValidator(
        known_ids=["aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"]
    )
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqRelatedIdExistenceIssue)
    assert issues[0].id == "12345678-1234-4234-8234-567812345678"


def test_validator_related_id_existence_mixed():
    validator = SigmahqRelatedIdExistenceValidator(
        known_ids=["aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"]
    )
    rule = _rule_with_related(
        "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqRelatedIdExistenceIssue)
    assert issues[0].id == "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"


def test_validator_related_id_existence_no_related():
    validator = SigmahqRelatedIdExistenceValidator(known_ids=[])
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


def test_validator_related_id_existence_unconfigured_skips():
    validator = SigmahqRelatedIdExistenceValidator()
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    with pytest.warns(UserWarning, match="no corpus index configured"):
        assert validator.validate(rule) == []


def test_validator_related_id_existence_warns_once(recwarn):
    validator = SigmahqRelatedIdExistenceValidator()
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    validator.validate(rule)
    validator.validate(rule)
    msgs = [str(w.message) for w in recwarn if "no corpus index configured" in str(w.message)]
    assert len(msgs) == 1


def test_validator_related_id_existence_case_insensitive():
    validator = SigmahqRelatedIdExistenceValidator(
        known_ids=["AAAAAAAA-AAAA-4AAA-AAAA-AAAAAAAAAAAA"]
    )
    rule = _rule_with_related("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
    assert validator.validate(rule) == []


def test_validator_related_id_existence_empty_known_ids_reports_missing():
    validator = SigmahqRelatedIdExistenceValidator(known_ids=[])
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqRelatedIdExistenceIssue)


def test_validator_related_id_existence_corpus_paths(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule_a.yml").write_text(
        "title: A\nid: 12345678-1234-4234-8234-567812345678\n",
        encoding="utf-8",
    )
    sub = rules_dir / "windows"
    sub.mkdir()
    (sub / "rule_b.yaml").write_text(
        "title: B\nid: aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa\n",
        encoding="utf-8",
    )
    validator = SigmahqRelatedIdExistenceValidator(corpus_paths=rules_dir)
    rule = _rule_with_related(
        "12345678-1234-4234-8234-567812345678",
        "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
    )
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert issues[0].id == "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"


def test_validator_related_id_existence_index_path_list(tmp_path):
    index = tmp_path / "ids.json"
    index.write_text(
        json.dumps(["12345678-1234-4234-8234-567812345678"]),
        encoding="utf-8",
    )
    validator = SigmahqRelatedIdExistenceValidator(index_path=index)
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    assert validator.validate(rule) == []


def test_validator_related_id_existence_index_path_dict(tmp_path):
    index = tmp_path / "ids.json"
    index.write_text(
        json.dumps({"ids": ["12345678-1234-4234-8234-567812345678"]}),
        encoding="utf-8",
    )
    validator = SigmahqRelatedIdExistenceValidator(index_path=index)
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    assert validator.validate(rule) == []


def test_validator_related_id_existence_invalid_corpus_path_skips(tmp_path):
    validator = SigmahqRelatedIdExistenceValidator(corpus_paths=tmp_path / "missing")
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    with pytest.warns(UserWarning):
        assert validator.validate(rule) == []


def test_validator_related_id_existence_setters(tmp_path):
    index = tmp_path / "ids.json"
    index.write_text(json.dumps(["12345678-1234-4234-8234-567812345678"]), encoding="utf-8")
    validator = SigmahqRelatedIdExistenceValidator()
    validator.set_index_path(index)
    rule = _rule_with_related("12345678-1234-4234-8234-567812345678")
    assert validator.validate(rule) == []

    validator.set_known_ids(["bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"])
    issues = validator.validate(rule)
    assert len(issues) == 1

    validator.clear_index()
    validator.set_known_ids(["12345678-1234-4234-8234-567812345678"])
    assert validator.validate(rule) == []


def test_validator_related_id_existence_scans_only_toplevel_id(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yml").write_text(
        """
title: A
id: 12345678-1234-4234-8234-567812345678
related:
    - type: derived
      id: deadbeef-dead-4ead-beef-deadbeefdead
""".lstrip(),
        encoding="utf-8",
    )
    validator = SigmahqRelatedIdExistenceValidator(corpus_paths=rules_dir)
    assert "12345678-1234-4234-8234-567812345678" in validator._get_index()
    assert "deadbeef-dead-4ead-beef-deadbeefdead" not in validator._get_index()


def test_validator_related_id_existence_scans_id_with_trailing_comment_and_quotes(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yml").write_text(
        "title: A\nid: 12345678-1234-4234-8234-567812345678 # SuspChild\n",
        encoding="utf-8",
    )
    (rules_dir / "b.yml").write_text(
        "title: B\nid: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'\n",
        encoding="utf-8",
    )
    validator = SigmahqRelatedIdExistenceValidator(corpus_paths=rules_dir)
    index = validator._get_index()
    assert "12345678-1234-4234-8234-567812345678" in index
    assert "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa" in index
    rule = _rule_with_related(
        "12345678-1234-4234-8234-567812345678",
        "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    )
    assert validator.validate(rule) == []


def test_validator_related_id_existence_loads_deprecated_json(tmp_path):
    repo = tmp_path / "repo"
    deprecated = repo / "deprecated"
    deprecated.mkdir(parents=True)
    (deprecated / "deprecated.json").write_text(
        json.dumps(
            [
                {
                    "id": "11111111-1111-4111-8111-111111111111",
                    "title": "Old",
                    "date": "2020-01-01",
                },
            ]
        ),
        encoding="utf-8",
    )
    validator = SigmahqRelatedIdExistenceValidator(corpus_paths=deprecated)
    rule = _rule_with_related("11111111-1111-4111-8111-111111111111")
    assert validator.validate(rule) == []


def test_validator_related_id_existence_expands_rules_to_deprecated_unsupported(tmp_path):
    repo = tmp_path / "repo"
    rules_dir = repo / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "r.yml").write_text("title: R\nid: aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa\n")
    deprecated = repo / "deprecated"
    deprecated.mkdir()
    (deprecated / "deprecated.json").write_text(
        json.dumps([{"id": "11111111-1111-4111-8111-111111111111"}]),
        encoding="utf-8",
    )
    unsupported = repo / "unsupported"
    unsupported.mkdir()
    (unsupported / "u.yml").write_text("title: U\nid: 22222222-2222-4222-8222-222222222222\n")

    validator = SigmahqRelatedIdExistenceValidator(corpus_paths=rules_dir)
    index = validator._get_index()
    assert "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa" in index
    assert "11111111-1111-4111-8111-111111111111" in index
    assert "22222222-2222-4222-8222-222222222222" in index


def test_validator_related_id_existence_auto_discovers_from_rule_source(tmp_path):
    repo = tmp_path / "repo"
    rules_dir = repo / "rules" / "windows"
    _write_rule(
        rules_dir / "rule.yml",
        "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
        related_ids=[
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        ],
    )
    deprecated = repo / "deprecated"
    deprecated.mkdir(parents=True)
    (deprecated / "deprecated.json").write_text(
        json.dumps([{"id": "11111111-1111-4111-8111-111111111111"}]),
        encoding="utf-8",
    )
    unsupported = repo / "unsupported"
    unsupported.mkdir()
    (unsupported / "u.yml").write_text("title: U\nid: 22222222-2222-4222-8222-222222222222\n")

    rule = list(SigmaCollection.load_ruleset([str(repo / "rules")]))[0]
    validator = SigmahqRelatedIdExistenceValidator()
    assert validator.validate(rule) == []


def test_validator_related_id_existence_auto_discovers_missing_unsupported(tmp_path):
    repo = tmp_path / "repo"
    rules_dir = repo / "rules"
    _write_rule(
        rules_dir / "rule.yml",
        "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
        related_ids=["33333333-3333-4333-8333-333333333333"],
    )
    (repo / "deprecated").mkdir(parents=True)
    (repo / "deprecated" / "deprecated.json").write_text("[]", encoding="utf-8")
    (repo / "unsupported").mkdir()
    (repo / "unsupported" / "u.yml").write_text(
        "title: U\nid: 44444444-4444-4444-8444-444444444444\n", encoding="utf-8"
    )

    rule = list(SigmaCollection.load_ruleset([str(repo / "rules")]))[0]
    validator = SigmahqRelatedIdExistenceValidator()
    issues = validator.validate(rule)
    assert len(issues) == 1
    assert issues[0].id == "33333333-3333-4333-8333-333333333333"
