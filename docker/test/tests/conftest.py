
pytest_plugins = ("cs",)


def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'docker: mark tests for lone or manually orchestrated containers'
    )
    config.addinivalue_line(
        'markers', 'compose: mark tests for docker compose projects'
    )
