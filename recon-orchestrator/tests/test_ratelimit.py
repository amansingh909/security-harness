import pytest

from recon_orchestrator.ratelimit import TokenBucket


def test_burst_up_to_capacity_is_free():
    bucket = TokenBucket(rate_per_sec=5, capacity=3)
    # three tokens available at t0 -> no wait
    assert bucket._take(0.0) == 0.0
    assert bucket._take(0.0) == 0.0
    assert bucket._take(0.0) == 0.0


def test_fourth_token_must_wait():
    bucket = TokenBucket(rate_per_sec=5, capacity=3)
    for _ in range(3):
        bucket._take(0.0)
    wait = bucket._take(0.0)  # bucket empty
    assert wait == pytest.approx(1 / 5, rel=1e-6)  # 0.2s at 5 rps


def test_refill_over_time():
    bucket = TokenBucket(rate_per_sec=10, capacity=1)
    assert bucket._take(0.0) == 0.0      # consume the one token
    assert bucket._take(0.05) == pytest.approx(0.05, rel=1e-6)  # half-refilled
    assert bucket._take(1.0) == 0.0      # fully refilled by t=1


def test_invalid_rate_rejected():
    with pytest.raises(ValueError):
        TokenBucket(rate_per_sec=0)
