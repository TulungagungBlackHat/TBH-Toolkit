import pytest

from toolkit.core.safety import SafetyError, check_loadtest_limits, is_lab_host, validate_target


def test_lab_hosts_allowed():
    assert is_lab_host("127.0.0.1")
    assert is_lab_host("localhost")
    assert is_lab_host("192.168.1.10")
    assert is_lab_host("example.com")


def test_external_blocked_by_default():
    with pytest.raises(SafetyError):
        validate_target("https://github.com")


def test_external_allowed_with_confirmation():
    assert validate_target("https://github.com", allow_external=True, confirm_external=True) == "github.com"


def test_lab_target_ok():
    assert validate_target("http://127.0.0.1:8000") == "127.0.0.1"


def test_loadtest_limits():
    check_loadtest_limits(100, 5, 2.0)
    with pytest.raises(SafetyError):
        check_loadtest_limits(99999, 5, 2.0)
    with pytest.raises(SafetyError):
        check_loadtest_limits(100, 99, 2.0)
