from pytest import mark

from loidreau.key import (
    generate,
    import_public_der,
    import_public_pem,
    import_secret_der,
    import_secret_pem,
)

from .util import load_secret_der


@mark.slow
@mark.parametrize(
    "security_level",
    [
        128,
        192,
        256,
    ],
)
def test_export_import_secret_der(security_level):
    original = generate(security_level)
    imported = import_secret_der(original.export_der())

    assert original.c().generator_matrix() == imported.c().generator_matrix()
    assert original.s() == imported.s()
    assert original.p() == imported.p()
    assert original._d == imported._d


@mark.parametrize(
    "security_level",
    [
        128,
        192,
        256,
    ],
)
def test_export_public_der(security_level):
    sk = load_secret_der(f"data/sk_{security_level}.der")

    original = sk.public_key()
    imported = import_public_der(original.export_der())

    assert original.g() == imported.g()
    assert original.delta() == imported.delta()


@mark.slow
@mark.parametrize(
    "security_level",
    [
        128,
        192,
        256,
    ],
)
def test_export_import_secret_pem(security_level):
    original = generate(security_level)
    imported = import_secret_pem(original.export_pem())

    assert original.c().generator_matrix() == imported.c().generator_matrix()
    assert original.s() == imported.s()
    assert original.p() == imported.p()
    assert original._d == imported._d


@mark.parametrize(
    "security_level",
    [
        128,
        192,
        256,
    ],
)
def test_export_public_pem(security_level):
    sk = load_secret_der(f"data/sk_{security_level}.der")

    original = sk.public_key()
    imported = import_public_pem(original.export_pem())

    assert original.g() == imported.g()
    assert original.delta() == imported.delta()
