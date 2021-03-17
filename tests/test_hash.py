from contextlib import nullcontext

from pytest import mark, param, raises
from loidreau.hash import SHA3, SHAKE


@mark.parametrize(
    "security_level, context",
    [
        param(0, raises(Exception)),
        (128, nullcontext()),
        (192, nullcontext()),
        (256, nullcontext()),
    ],
)
def test_hash_sha3_construction(security_level, context):
    with context:
        SHA3(security_level)


@mark.parametrize(
    "security_level, digest_size",
    [
        (128, 32),
        (192, 48),
        (256, 64),
    ],
)
def test_hash_sha3_digest_size(security_level, digest_size):
    hash_function = SHA3(security_level)

    assert hash_function.digest_size() == digest_size
    assert len(hash_function(b"")) == digest_size


@mark.parametrize(
    "security_level, context",
    [
        param(0, raises(Exception)),
        (128, nullcontext()),
        (192, nullcontext()),
        (256, nullcontext()),
    ],
)
def test_hash_shake_construction(security_level, context):
    with context:
        SHAKE(security_level)


@mark.parametrize(
    "security_level, digest_size",
    [
        (128, 6),
        (128, 28),
        (128, 128),
        (192, 105),
        (192, 145),
        (192, 192),
        (256, 81),
        (256, 126),
        (256, 256),
    ],
)
def test_hash_shake_digest_size(security_level, digest_size):
    hash_function = SHAKE(security_level)
    assert len(hash_function(b"", digest_size)) == digest_size
