"""Shared test fixtures."""
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def malicious_tools_file():
    return str(FIXTURES_DIR / "malicious_tools.json")


@pytest.fixture
def clean_tools_file():
    return str(FIXTURES_DIR / "clean_tools.json")


@pytest.fixture
def malicious_source_dir():
    return str(FIXTURES_DIR / "malicious_source")


@pytest.fixture
def clean_source_dir():
    return str(FIXTURES_DIR / "clean_source")
