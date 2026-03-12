"""Smoke tests for the report-worker package."""


def test_reporter_package_imports() -> None:
    """Verify the reporter package can be imported."""
    import reporter
    assert reporter.__doc__ is not None


def test_worker_module_imports() -> None:
    """Verify reporter.worker module imports without errors."""
    from reporter import worker
    assert worker.__doc__ is not None
