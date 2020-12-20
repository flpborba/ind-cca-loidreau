from loidreau import __version__


def test_version():
    assert __version__ == "0.1.0"


def test_sage_installation():
    import sage  # noqa: F401
