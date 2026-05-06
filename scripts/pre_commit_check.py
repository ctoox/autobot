#!/usr/bin/env python
"""Pre-commit hook script for running security checks."""
import subprocess
import sys


def run_check(cmd: str, name: str) -> bool:
    print(f"Running {name}...")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[FAIL] {name}")
        print(result.stdout)
        print(result.stderr)
        return False
    print(f"[PASS] {name}")
    return True


def main():
    checks = [
        ("ruff check src/ tests/", "Ruff linting"),
        ("black --check src/ tests/", "Black formatting"),
        ("mypy src/", "Mypy type checking"),
        ("bandit -r src/ -ll", "Bandit security scan"),
        ("pytest tests/unit -q", "Unit tests"),
    ]

    all_passed = True
    for cmd, name in checks:
        if not run_check(cmd, name):
            all_passed = False

    if not all_passed:
        print("\nSome checks failed. Please fix before committing.")
        sys.exit(1)
    else:
        print("\nAll checks passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
