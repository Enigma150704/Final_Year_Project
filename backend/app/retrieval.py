from pathlib import Path
import ast
import re
from typing import List, Dict, Any, Optional
from .security import is_source_file, should_ignore, redact_secret_text

def _is_safe_repo_path(repo: Path, target_path: Path) -> bool:
    """Ensure the target path is strictly inside the repository root."""
    try:
        resolved_repo = repo.resolve()
        resolved_target = target_path.resolve()
        return resolved_repo in resolved_target.parents or resolved_target == resolved_repo
    except Exception:
        return False

def _extract_python_enclosing_scope(file_content: str, line_no: int) -> Optional[Dict[str, Any]]:
    """Use Python AST to accurately locate enclosing function, async function or class."""
    try:
        tree = ast.parse(file_content)
    except SyntaxError:
        return None

    enclosing = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start and end and start <= line_no <= end:
                # Keep the most specific (innermost) match
                if enclosing is None or (end - start) < (enclosing["end_line"] - enclosing["start_line"]):
                    kind = "class" if isinstance(node, ast.ClassDef) else "function"
                    enclosing = {
                        "scope_name": node.name,
                        "scope_type": kind,
                        "start_line": start,
                        "end_line": end,
                        "method": "ast"
                    }
    return enclosing

def _extract_lexical_enclosing_scope(lines: List[str], line_no: int) -> Optional[Dict[str, Any]]:
    """Lexical fallback to identify enclosing function/method in JS, TS, Java or unparsed code."""
    idx = min(len(lines) - 1, max(0, line_no - 1))
    # Look backwards up to 50 lines for a function or class signature
    func_pattern = re.compile(
        r'^\s*(?:(?:public|private|protected|static|final|async)\s+)*(?:function\s+([A-Za-z0-9_$]+)|(?:class|interface)\s+([A-Za-z0-9_$]+)|(?:[A-Za-z0-9_<>[\]]+\s+)+([A-Za-z0-9_$]+)\s*\([^)]*\)|const\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|def\s+([A-Za-z0-9_]+))'
    )
    for i in range(idx, max(-1, idx - 50), -1):
        line = lines[i]
        m = func_pattern.search(line)
        if m:
            name = next((g for g in m.groups() if g), "anonymous_scope")
            return {
                "scope_name": name,
                "scope_type": "lexical_block",
                "start_line": i + 1,
                "end_line": min(len(lines), idx + 10),
                "method": "lexical"
            }
    return None

def retrieve_context(repo: Path, finding: Any, max_files: int = 5, max_chars: int = 12000) -> List[Dict[str, Any]]:
    """
    Retrieve repository context for a finding:
    1. Enclosing function or class (AST where possible, lexical fallback).
    2. Primary finding line range with surrounding lines.
    3. Related files scored by identifier and token overlap.
    All returned contents are strictly sanitized and secrets-redacted.
    """
    results: List[Dict[str, Any]] = []
    primary_path = repo / finding.file
    
    if not _is_safe_repo_path(repo, primary_path):
        return results

    primary_content = ""
    lines: List[str] = []
    if primary_path.exists() and primary_path.is_file():
        try:
            primary_content = primary_path.read_text(encoding="utf-8", errors="ignore")
            lines = primary_content.splitlines()
        except OSError:
            pass

    # 1. Enclosing function/class detection
    if lines:
        scope = None
        ext = primary_path.suffix.lower()
        if ext == ".py":
            scope = _extract_python_enclosing_scope(primary_content, finding.start_line)
        if not scope:
            scope = _extract_lexical_enclosing_scope(lines, finding.start_line)

        if scope:
            s_line = max(1, scope["start_line"])
            e_line = min(len(lines), scope["end_line"])
            snippet = "\n".join(f"{i}: {lines[i-1]}" for i in range(s_line, e_line + 1))
            redacted_snippet = redact_secret_text(snippet)
            results.append({
                "file": finding.file,
                "context_type": "enclosing_scope",
                "relevance": f"Enclosing {scope['scope_type']} `{scope['scope_name']}` ({scope['method']})",
                "line_start": s_line,
                "line_end": e_line,
                "retrieval_method": scope["method"],
                "content": redacted_snippet[:max_chars // 2]
            })

    # 2. Primary finding surrounding lines (+/- 6 lines)
    if lines:
        s_line = max(1, finding.start_line - 6)
        e_line = min(len(lines), finding.end_line + 6)
        snippet = "\n".join(f"{i}: {lines[i-1]}" for i in range(s_line, e_line + 1))
        results.append({
            "file": finding.file,
            "context_type": "surrounding_lines",
            "relevance": f"Exact finding location lines {finding.start_line}-{finding.end_line}",
            "line_start": s_line,
            "line_end": e_line,
            "retrieval_method": "source_offset",
            "content": redact_secret_text(snippet)
        })

    # 3. Related source files by token & identifier matching
    tokens = set((finding.title + " " + finding.description + " " + getattr(finding, "category", "")).lower().split())
    identifiers = set()
    for word in primary_content.split():
        cleaned = "".join(c for c in word if c.isalnum() or c == "_")
        if len(cleaned) >= 5 and cleaned.isidentifier():
            identifiers.add(cleaned.lower())

    scored = []
    for p in repo.rglob("*"):
        if p == primary_path or not is_source_file(p) or should_ignore(p.relative_to(repo)):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")[:100000]
        except OSError:
            continue
        
        low = text.lower()
        score = sum(1 for token in tokens if token and token in low)
        score += sum(1 for ident in list(identifiers)[:60] if ident in low)
        if score > 0:
            scored.append((score, p, text))

    scored.sort(key=lambda x: x[0], reverse=True)
    for score, p, text in scored[:max_files - 1]:
        rel = str(p.relative_to(repo)).replace("\\", "/")
        results.append({
            "file": rel,
            "context_type": "related_file",
            "relevance": f"Related code lexical match (score: {score})",
            "line_start": 1,
            "line_end": min(len(text.splitlines()), 60),
            "retrieval_method": "lexical_overlap",
            "content": redact_secret_text(text[:max(1000, max_chars // max_files)])
        })

    return results
