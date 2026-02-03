
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _pytest.config import Config

pytest_plugins = ("cs",)


def pytest_configure(config: Config) -> None:
    config.addinivalue_line("markers", "docker: mark tests for lone or manually orchestrated containers")
    config.addinivalue_line("markers", "compose: mark tests for docker compose projects")
