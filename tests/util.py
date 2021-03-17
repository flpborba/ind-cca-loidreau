from loidreau.key import import_public_der, import_secret_der


def load_secret_der(filename):
    data = open(filename, "rb").read()
    return import_secret_der(data)


def load_public_der(filename):
    data = open(filename, "rb").read()
    return import_public_der(data)
