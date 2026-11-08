import json
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Iterable, List, Optional, Set
from uuid import UUID

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

_ID_LINE_RE = re.compile(
    r"(?m)^id:\s*['\"]?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})['\"]?\s*(?:#.*)?$"
)
_RULES_DIR_RE = re.compile(r"^rules($|[-_].*)")


@dataclass
class SigmahqRelatedIdentifierIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule related id is not a valid UUID v4"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    id: str


class SigmahqRelatedIdentifierValidator(SigmaRuleValidator):
    """Checks if a rule related ids are valid UUID v4 (RFC 4122 / RFC 9562)."""

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if rule.related:
            issues = []
            for related_item in rule.related.related:
                if related_item.id.version != 4:
                    issues.append(SigmahqRelatedIdentifierIssue([rule], str(related_item.id)))
            return issues
        return []


@dataclass
class SigmahqRelatedIdExistenceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule related id does not exist in the known SigmaHQ corpus"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    id: str


class SigmahqRelatedIdExistenceValidator(SigmaRuleValidator):
    """Checks that rule related ids exist in a known SigmaHQ corpus index.

    The index is built lazily from ``corpus_paths`` (recursive scan of rule YAML
    files and known index manifests such as ``deprecated.json``), ``index_path``
    (a precomputed JSON list of ids), or ``known_ids``. When explicit config is
    absent, the validator tries to auto-discover a SigmaHQ repository root from
    ``rule.source.path`` and indexes ``rules*``, ``deprecated`` and ``unsupported``.
    When no index can be resolved the check is skipped and no issues are reported,
    to avoid false positives outside a corpus context.
    """

    def __init__(
        self,
        corpus_paths: str | Path | Iterable[str | Path] | None = None,
        index_path: str | Path | None = None,
        known_ids: Iterable[str | UUID] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._corpus_paths = self._normalize_corpus_paths(corpus_paths)
        self._index_path = Path(index_path) if index_path is not None else None
        self._known_ids_input: Optional[Set[str]] = (
            {self._normalize_id(v) for v in known_ids} if known_ids is not None else None
        )
        self._index: Optional[Set[str]] = None
        self._discovery_attempted = False
        self._warned_no_index = False

    @staticmethod
    def _normalize_id(value: str | UUID) -> str:
        return str(value).lower()

    @staticmethod
    def _normalize_corpus_paths(
        corpus_paths: str | Path | Iterable[str | Path] | None,
    ) -> List[Path]:
        if corpus_paths is None:
            return []
        if isinstance(corpus_paths, (str, Path)):
            return [Path(corpus_paths)]
        return [Path(p) for p in corpus_paths]

    def set_corpus_paths(self, corpus_paths: str | Path | Iterable[str | Path] | None) -> None:
        self._corpus_paths = self._normalize_corpus_paths(corpus_paths)
        self._reset_index()

    def set_index_path(self, index_path: str | Path | None) -> None:
        self._index_path = Path(index_path) if index_path is not None else None
        self._reset_index()

    def set_known_ids(self, known_ids: Iterable[str | UUID] | None) -> None:
        self._known_ids_input = (
            {self._normalize_id(v) for v in known_ids} if known_ids is not None else None
        )
        self._reset_index()

    def clear_index(self) -> None:
        self._reset_index()

    def _reset_index(self) -> None:
        self._index = None
        self._discovery_attempted = False
        self._warned_no_index = False

    def _has_explicit_config(self) -> bool:
        return (
            self._known_ids_input is not None
            or self._index_path is not None
            or bool(self._corpus_paths)
        )

    def _extract_ids_from_json_data(self, data: Any) -> Set[str]:
        if isinstance(data, dict):
            if "ids" in data and isinstance(data["ids"], list):
                data = data["ids"]
            else:
                data = [v.get("id") for v in data.values() if isinstance(v, dict)]
        if not isinstance(data, list):
            return set()
        ids: Set[str] = set()
        for item in data:
            if isinstance(item, (str, UUID)):
                ids.add(self._normalize_id(item))
            elif isinstance(item, dict) and "id" in item and isinstance(item["id"], (str, UUID)):
                ids.add(self._normalize_id(item["id"]))
        return ids

    def _load_index_from_path(self, index_path: Path) -> Set[str]:
        try:
            with index_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            warnings.warn(
                f"SigmahqRelatedIdExistenceValidator: could not load index '{index_path}': {exc}",
                stacklevel=3,
            )
            return set()
        ids = self._extract_ids_from_json_data(data)
        if not ids:
            warnings.warn(
                f"SigmahqRelatedIdExistenceValidator: index '{index_path}' did not "
                "contain recognizable ids",
                stacklevel=3,
            )
        return ids

    def _load_manifest_ids(self, path: Path) -> Set[str]:
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, ValueError):
            return set()
        return self._extract_ids_from_json_data(data)

    def _expand_corpus_paths(self, corpus_paths: List[Path]) -> List[Path]:
        expanded: List[Path] = []
        seen: Set[Path] = set()

        def add(path: Path) -> None:
            resolved = path
            if resolved not in seen:
                seen.add(resolved)
                expanded.append(resolved)

        for path in corpus_paths:
            add(path)
            name = path.name
            if _RULES_DIR_RE.match(name):
                for sibling in ("deprecated", "unsupported"):
                    sibling_path = path.parent / sibling
                    if sibling_path.exists():
                        add(sibling_path)
        return expanded

    def _find_repo_root(self, source_path: Path) -> Optional[Path]:
        try:
            current = source_path.resolve()
        except OSError:
            current = source_path
        if current.is_file():
            current = current.parent
        for directory in [current, *current.parents]:
            has_extra = (directory / "deprecated").exists() or (directory / "unsupported").exists()
            has_rules = (
                any(p.is_dir() and _RULES_DIR_RE.match(p.name) for p in directory.iterdir())
                if directory.exists()
                else False
            )
            has_marker = (directory / "tests" / "sigma_cli_conf.yml").exists()
            if (has_extra and has_rules) or (has_marker and has_rules):
                return directory
        return None

    def _discover_corpus_paths(
        self, rule: SigmaRule | SigmaCorrelationRule
    ) -> Optional[List[Path]]:
        source = getattr(rule, "source", None)
        if source is None:
            return None
        source_path = getattr(source, "path", source)
        if source_path is None:
            return None
        try:
            path = Path(source_path)
        except (TypeError, ValueError):
            return None
        root = self._find_repo_root(path)
        if root is None:
            return None
        paths: List[Path] = []
        try:
            for child in sorted(root.iterdir()):
                if child.is_dir() and _RULES_DIR_RE.match(child.name):
                    paths.append(child)
        except OSError:
            return None
        for extra in ("deprecated", "unsupported"):
            extra_path = root / extra
            if extra_path.exists():
                paths.append(extra_path)
        return paths or None

    def _scan_corpus_paths(self, corpus_paths: List[Path]) -> Set[str]:
        known: Set[str] = set()
        found_any = False
        for root in self._expand_corpus_paths(corpus_paths):
            try:
                if not root.exists():
                    warnings.warn(
                        f"SigmahqRelatedIdExistenceValidator: corpus path '{root}' does not exist",
                        stacklevel=4,
                    )
                    continue
                found_any = True
                if root.is_file():
                    if root.suffix.lower() == ".json":
                        known.update(self._load_manifest_ids(root))
                    else:
                        self._scan_rule_file(root, known)
                    continue
                manifest = root / "deprecated.json"
                if manifest.is_file():
                    known.update(self._load_manifest_ids(manifest))
                for json_path in root.rglob("deprecated.json"):
                    if json_path != manifest:
                        known.update(self._load_manifest_ids(json_path))
                for path in list(root.rglob("*.yml")) + list(root.rglob("*.yaml")):
                    self._scan_rule_file(path, known)
            except OSError as exc:
                warnings.warn(
                    f"SigmahqRelatedIdExistenceValidator: failed to scan corpus path "
                    f"'{root}': {exc}",
                    stacklevel=4,
                )
        if not found_any and corpus_paths:
            return set()
        return known

    def _scan_rule_file(self, path: Path, known: Set[str]) -> None:
        if not path.is_file():
            return
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        match = _ID_LINE_RE.search(text)
        if match:
            known.add(match.group(1).lower())

    def _get_index(self, rule: SigmaRule | SigmaCorrelationRule | None = None) -> Set[str]:
        if self._index is not None:
            return self._index

        if self._known_ids_input is not None:
            self._index = set(self._known_ids_input)
            return self._index

        if self._index_path is not None:
            self._index = self._load_index_from_path(self._index_path)
            return self._index

        if self._corpus_paths:
            self._index = self._scan_corpus_paths(self._corpus_paths)
            return self._index

        if rule is not None and not self._discovery_attempted:
            self._discovery_attempted = True
            discovered = self._discover_corpus_paths(rule)
            if discovered:
                self._index = self._scan_corpus_paths(discovered)
                return self._index

        self._index = set()
        return self._index

    def _warn_no_index_once(self) -> None:
        if not self._warned_no_index:
            self._warned_no_index = True
            warnings.warn(
                "SigmahqRelatedIdExistenceValidator: no corpus index configured or "
                "discoverable; existence check skipped. Configure corpus_paths, "
                "index_path, or known_ids to enable it.",
                stacklevel=4,
            )

    def validate(self, rule: SigmaRule | SigmaCorrelationRule) -> List[SigmaValidationIssue]:
        if not rule.related:
            return []

        if not self._has_explicit_config():
            index = self._get_index(rule)
            if not index:
                self._warn_no_index_once()
                return []
        else:
            index = self._get_index(rule)
            if not index and self._known_ids_input is None:
                # Explicit source configured but resolution failed/empty; skip.
                return []

        issues: List[SigmaValidationIssue] = []
        for related_item in rule.related.related:
            related_id = self._normalize_id(related_item.id)
            if related_id not in index:
                issues.append(SigmahqRelatedIdExistenceIssue([rule], str(related_item.id)))
        return issues
