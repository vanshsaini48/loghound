import pytest
import yaml
from pathlib import Path

@pytest.fixture
def test_config():
    """Load test config from YAML."""
    with open(Path('tests/fixtures/test_config.yaml')) as f:
        return yaml.safe_load(f)
