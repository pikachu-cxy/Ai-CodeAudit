"""Static Java dependency parsing from pom.xml / Gradle build files."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from app.services.path_filters import BASE_SKIP_DIRS, should_skip_walk_path

_SKIP = set(BASE_SKIP_DIRS) | {"node_modules", ".git"}

_GRADLE_DEP_RE = re.compile(
    r"""(?P<cfg>implementation|api|compileOnly|runtimeOnly|compile|runtime)\s*
        (?:\(\s*)?
        ['"](?P<coord>[^'"]+)['"]
    """,
    re.VERBOSE,
)

_GRADLE_MAP_RE = re.compile(
    r"""(?P<cfg>implementation|api|compileOnly|runtimeOnly|compile|runtime)\s*
        (?:\(\s*)?
        group\s*:\s*['"](?P<group>[^'"]+)['"]\s*,\s*
        name\s*:\s*['"](?P<name>[^'"]+)['"]\s*,\s*
        version\s*:\s*['"](?P<version>[^'"]+)['"]
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class JavaDependency:
    group_id: str
    artifact_id: str
    version: str
    declared_in: str
    line: int = 0

    @property
    def package(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


def has_java_manifest(project_path: Path) -> bool:
    root = project_path.resolve()
    if (root / "pom.xml").is_file():
        return True
    for name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        if (root / name).is_file():
            return True
    for path in _iter_manifest_files(root):
        return True
    return False


def _iter_manifest_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if should_skip_walk_path(path, _SKIP, relative_to=root):
            continue
        name = path.name.lower()
        if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            yield path


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _child_text(elem: ET.Element, name: str) -> str:
    for child in list(elem):
        if _local_name(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _resolve_props(text: str, props: dict[str, str], depth: int = 0) -> str:
    if not text or depth > 6:
        return text

    def repl(m: re.Match[str]) -> str:
        key = m.group(1)
        return props.get(key, m.group(0))

    out = re.sub(r"\$\{([^}]+)\}", repl, text)
    if out != text:
        return _resolve_props(out, props, depth + 1)
    return out


def _collect_pom_properties(root: ET.Element) -> dict[str, str]:
    props: dict[str, str] = {}
    for props_el in root.iter():
        if _local_name(props_el.tag) != "properties":
            continue
        for child in list(props_el):
            key = _local_name(child.tag)
            if key:
                props[key] = (child.text or "").strip()
    # Common Maven implicit properties
    for el in root.iter():
        if _local_name(el.tag) != "project":
            continue
        # only top-ish; still fine for single-module
        version = _child_text(el, "version")
        if version:
            props.setdefault("project.version", version)
            props.setdefault("version", version)
        group = _child_text(el, "groupId")
        if group:
            props.setdefault("project.groupId", group)
            props.setdefault("groupId", group)
        artifact = _child_text(el, "artifactId")
        if artifact:
            props.setdefault("project.artifactId", artifact)
            props.setdefault("artifactId", artifact)
        parent = None
        for child in list(el):
            if _local_name(child.tag) == "parent":
                parent = child
                break
        if parent is not None:
            pv = _child_text(parent, "version")
            if pv:
                props.setdefault("project.parent.version", pv)
                props.setdefault("parent.version", pv)
        break
    return props


def _dep_line_in_pom(text: str, group: str, artifact: str) -> int:
    # Best-effort: locate first artifactId occurrence near groupId.
    pattern = re.compile(
        rf"<groupId>\s*{re.escape(group)}\s*</groupId>[\s\S]{{0,200}}?"
        rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>",
        re.IGNORECASE,
    )
    m = pattern.search(text)
    if not m:
        pattern2 = re.compile(rf"<artifactId>\s*{re.escape(artifact)}\s*</artifactId>", re.I)
        m = pattern2.search(text)
    if not m:
        return 0
    return text.count("\n", 0, m.start()) + 1


def parse_pom_dependencies(pom_path: Path, project_root: Path | None = None) -> list[JavaDependency]:
    root_path = (project_root or pom_path.parent).resolve()
    try:
        text = pom_path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(text)
    except (OSError, ET.ParseError):
        return []

    props = _collect_pom_properties(root)
    rel = str(pom_path.resolve().relative_to(root_path)).replace("\\", "/")
    out: list[JavaDependency] = []
    seen: set[tuple[str, str, str]] = set()

    for dep in root.iter():
        if _local_name(dep.tag) != "dependency":
            continue
        group = _resolve_props(_child_text(dep, "groupId"), props)
        artifact = _resolve_props(_child_text(dep, "artifactId"), props)
        version = _resolve_props(_child_text(dep, "version"), props)
        if not group or not artifact or not version:
            continue
        if version.startswith("${"):
            continue
        key = (group, artifact, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            JavaDependency(
                group_id=group,
                artifact_id=artifact,
                version=version,
                declared_in=rel,
                line=_dep_line_in_pom(text, group, artifact),
            )
        )
    return out


def parse_gradle_dependencies(gradle_path: Path, project_root: Path | None = None) -> list[JavaDependency]:
    root_path = (project_root or gradle_path.parent).resolve()
    try:
        text = gradle_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(gradle_path.resolve().relative_to(root_path)).replace("\\", "/")
    out: list[JavaDependency] = []
    seen: set[tuple[str, str, str]] = set()

    def add(group: str, artifact: str, version: str, start: int) -> None:
        if not group or not artifact or not version:
            return
        if version.startswith("$") or version.startswith("{"):
            return
        key = (group, artifact, version)
        if key in seen:
            return
        seen.add(key)
        line = text.count("\n", 0, start) + 1
        out.append(
            JavaDependency(
                group_id=group,
                artifact_id=artifact,
                version=version,
                declared_in=rel,
                line=line,
            )
        )

    for m in _GRADLE_DEP_RE.finditer(text):
        coord = m.group("coord").strip()
        parts = coord.split(":")
        if len(parts) >= 3:
            add(parts[0], parts[1], parts[2], m.start())
    for m in _GRADLE_MAP_RE.finditer(text):
        add(m.group("group"), m.group("name"), m.group("version"), m.start())
    return out


def parse_java_dependencies(project_path: Path) -> list[JavaDependency]:
    """Collect declared dependencies from pom.xml / Gradle files under project."""
    root = project_path.resolve()
    deps: list[JavaDependency] = []
    for path in _iter_manifest_files(root):
        name = path.name.lower()
        if name == "pom.xml":
            deps.extend(parse_pom_dependencies(path, root))
        elif name in ("build.gradle", "build.gradle.kts"):
            deps.extend(parse_gradle_dependencies(path, root))
    # Prefer first declaration per package (root manifests usually first via rglob order).
    by_pkg: dict[str, JavaDependency] = {}
    for dep in deps:
        key = dep.package.lower()
        if key not in by_pkg:
            by_pkg[key] = dep
    return list(by_pkg.values())
