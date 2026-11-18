from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List
from .security import is_source_file, should_ignore

EXT_TO_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript/React",
    ".ts": "TypeScript", ".tsx": "TypeScript/React", ".java": "Java",
    ".go": "Go", ".php": "PHP", ".rb": "Ruby", ".cs": "C#",
    ".cpp": "C++", ".c": "C", ".h": "C/C++ Header", ".sql": "SQL"
}

FRAMEWORK_MARKERS = {
    "FastAPI": ["fastapi"], "Flask": ["flask"], "Django": ["django"],
    "Express": ["express"], "React": ["react"], "Next.js": ["next"],
    "Spring Boot": ["spring-boot", "springframework"], "Vue.js": ["vue"]
}

DEPENDENCY_FILES = {
    "requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod",
    "Cargo.toml", "Gemfile", "composer.json"
}

ENTRYPOINT_NAMES = {
    "main.py", "app.py", "manage.py", "server.js", "index.js",
    "main.ts", "Application.java", "Program.cs"
}

def profile_repository(project_id: str, project_name: str, repo: Path) -> Dict[str, Any]:
    """
    Profile repository safely without executing any source files, scripts, or build manifests.
    """
    counts = Counter()
    dependency_files: List[str] = []
    entrypoints: List[str] = []
    files: List[Path] = []
    total_bytes = 0

    for p in repo.rglob("*"):
        if should_ignore(p.relative_to(repo)):
            continue
        if not p.is_file():
            continue
        
        files.append(p)
        try:
            total_bytes += p.stat().st_size
        except OSError:
            pass

        norm_rel = str(p.relative_to(repo)).replace("\\", "/")
        if p.suffix.lower() in EXT_TO_LANG:
            counts[EXT_TO_LANG[p.suffix.lower()]] += 1
        if p.name in DEPENDENCY_FILES:
            dependency_files.append(norm_rel)
        if p.name in ENTRYPOINT_NAMES:
            entrypoints.append(norm_rel)

    detected_text = ""
    for p in files:
        if p.name in DEPENDENCY_FILES:
            try:
                detected_text += p.read_text(encoding="utf-8", errors="ignore").lower()[:200000]
            except OSError:
                pass

    frameworks = []
    for framework, markers in FRAMEWORK_MARKERS.items():
        if any(marker in detected_text for marker in markers):
            frameworks.append(framework)

    warnings = []
    if not counts:
        warnings.append("No common programming language files detected.")

    return {
        "project_id": project_id,
        "project_name": project_name,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "languages": dict(counts),
        "frameworks": frameworks,
        "dependency_files": sorted(dependency_files),
        "manifests": sorted(dependency_files),
        "entrypoint_candidates": sorted(entrypoints),
        "warnings": warnings,
        "scanned_at": datetime.now(timezone.utc).isoformat()
    }
