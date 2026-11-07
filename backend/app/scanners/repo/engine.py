import os
from typing import List, Dict, Any, Tuple
from app.scanners.repo.secrets import scan_file_for_secrets
from app.scanners.repo.sast import scan_file_for_sast
from app.scanners.repo.sca import scan_file_for_sca
from app.risk.engine import calculate_posture_score

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

IGNORED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
    ".exe",
    ".bin",
    ".pyc",
}

MAX_FILES_TO_SCAN = 500
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2MB


class RepoSecurityScanner:
    """Security scanner for code repositories implementing Secret Scanning, SAST, and SCA."""

    @classmethod
    def scan_file_content(cls, file_path: str, content: str) -> List[Dict[str, Any]]:
        """Run all scanner engines against a single file's text content."""
        findings: List[Dict[str, Any]] = []

        # 1. Secret scanning
        findings.extend(scan_file_for_secrets(file_path, content))

        # 2. SAST code security checks
        findings.extend(scan_file_for_sast(file_path, content))

        # 3. SCA dependency vulnerabilities
        findings.extend(scan_file_for_sca(file_path, content))

        return findings

    @classmethod
    def scan_virtual_files(cls, files: Dict[str, str]) -> Tuple[int, Dict[str, int], List[Dict[str, Any]]]:
        """Scan an in-memory dictionary of {file_path: content}."""
        all_findings: List[Dict[str, Any]] = []

        for path, content in list(files.items())[:MAX_FILES_TO_SCAN]:
            all_findings.extend(cls.scan_file_content(path, content))

        # Compute metrics
        counts = {
            "findings_count": len(all_findings),
            "secret_count": sum(1 for f in all_findings if f["scan_type"] == "secret"),
            "sast_count": sum(1 for f in all_findings if f["scan_type"] == "sast"),
            "sca_count": sum(1 for f in all_findings if f["scan_type"] == "sca"),
            "critical_count": sum(1 for f in all_findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in all_findings if f["severity"] == "high"),
            "medium_count": sum(1 for f in all_findings if f["severity"] == "medium"),
            "low_count": sum(1 for f in all_findings if f["severity"] == "low"),
        }

        # Calculate posture score using deterministic risk engine
        score, _, _ = calculate_posture_score([{"severity": f["severity"]} for f in all_findings])

        return score, counts, all_findings

    @classmethod
    def scan_local_directory(cls, dir_path: str) -> Tuple[int, Dict[str, int], List[Dict[str, Any]]]:
        """Walk and scan a local repository directory safely within resource boundaries."""
        virtual_files: Dict[str, str] = {}
        files_scanned = 0

        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]

            for fname in files:
                if files_scanned >= MAX_FILES_TO_SCAN:
                    break

                ext = os.path.splitext(fname)[1].lower()
                if ext in IGNORED_EXTENSIONS:
                    continue

                full_path = os.path.join(root, fname)
                try:
                    if os.path.getsize(full_path) > MAX_FILE_SIZE_BYTES:
                        continue

                    rel_path = os.path.relpath(full_path, dir_path).replace("\\", "/")
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        virtual_files[rel_path] = f.read()
                        files_scanned += 1
                except Exception:
                    continue

        return cls.scan_virtual_files(virtual_files)
