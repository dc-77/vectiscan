"""Smoke test — ensures worker module can be imported."""


def test_worker_import() -> None:
    """Verify scanner.worker module imports without errors."""
    from scanner.worker import main
    assert callable(main)
