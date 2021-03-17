from abc import ABC

import sage.all  # noqa: F401 (required by sage)
from Crypto.IO import PEM
from Crypto.Util.asn1 import DerBitString, DerOctetString, DerSequence
from sage.coding.gabidulin_code import GabidulinCode
from sage.matrix.matrix_space import MatrixSpace
from sage.matrix.special import identity_matrix
from sage.modules.free_module import VectorSpace
from sage.rings.finite_rings.finite_field_constructor import GF

from loidreau.io import decode, decode_elem_list, encode, encode_elem_list
from loidreau.matrix import (
    random_invertible_matrix,
    random_invertible_subpace_matrix,
    random_rank_vector,
)


class Key(ABC):
    def m(self):
        NotImplemented

    def n(self):
        NotImplemented

    def k(self):
        NotImplemented

    def delta(self):
        NotImplemented


class SecretKey(Key):
    def __init__(self, c, s, p, delta):
        self._c = c
        self._s = s
        self._p = p
        self._d = delta

    def public_key(self):
        g = self._s.inverse() * self._c.generator_matrix() * self._p.inverse()
        return PublicKey(g, self._d)

    def export_pem(self):
        der_encoded = self.export_der()
        marker = "PRIVATE KEY"

        return PEM.encode(der_encoded, marker)

    def export_der(self):
        parameters = [
            self._c.base_field().degree(),
            self._c.length(),
            self._c.dimension(),
            self._d,
        ]

        sequence = [
            DerOctetString(encode_elem_list(self.c().evaluation_points())),
            DerOctetString(encode(self.s())),
            DerOctetString(encode(self.p())),
            DerSequence(parameters),
        ]

        return DerSequence(sequence).encode()

    def c(self):
        return self._c

    def s(self):
        return self._s

    def p(self):
        return self._p

    def m(self):
        return self._c.base_ring().degree()

    def n(self):
        return self._c.length()

    def k(self):
        return self._c.dimension()

    def delta(self):
        return self._d


class PublicKey(Key):
    def __init__(self, g, delta):
        self._g = g
        self._d = delta

    def export_pem(self):
        der_encoded = self.export_der()
        marker = "PUBLIC KEY"

        return PEM.encode(der_encoded, marker)

    def export_der(self):
        parameters = [
            self._g.base_ring().degree(),
            self._g.ncols(),
            self._g.nrows(),
            self._d,
        ]

        sequence = [
            DerBitString(encode(self._g.submatrix(0, self._g.nrows()))),
            DerSequence(parameters),
        ]

        return DerSequence(sequence).encode()

    def g(self):
        return self._g

    def m(self):
        return self._g.base_ring().degree()

    def n(self):
        return self._g.ncols()

    def k(self):
        return self._g.nrows()

    def delta(self):
        return self._d


def generate(security_level):
    m, n, k, delta = _select_parameters(security_level)

    c = _random_gabidulin_code(m, n, k)
    s = random_invertible_matrix(GF(2 ** m), k)
    p = random_invertible_subpace_matrix(GF(2 ** m), delta, n)

    t = s * c.generator_matrix() * p.inverse()
    s = s.inverse() * t.submatrix(ncols=k)

    return SecretKey(c, s, p, delta)


def import_secret_pem(data):
    der_encoded, marker, _ = PEM.decode(data)

    if marker != "PRIVATE KEY":
        raise ValueError("invalid PEM-encoded private key")

    return import_secret_der(der_encoded)


def import_secret_der(data):
    *key, parameters = DerSequence().decode(data)

    key = [DerOctetString().decode(item).payload for item in key]
    m, n, k, delta = DerSequence().decode(parameters)

    extension_field = GF(2 ** m)
    points = decode_elem_list(key[0], extension_field)

    c = GabidulinCode(extension_field, n, k, evaluation_points=points)
    s = decode(key[1], MatrixSpace(extension_field, k))
    p = decode(key[2], MatrixSpace(extension_field, n))

    return SecretKey(c, s, p, delta)


def import_public_pem(data):
    der_encoded, marker, _ = PEM.decode(data)

    if marker != "PUBLIC KEY":
        raise ValueError("invalid PEM-encoded public key")

    return import_public_der(der_encoded)


def import_public_der(data):
    key, parameters = DerSequence().decode(data)

    key = DerBitString().decode(key).payload[1:]
    m, n, k, delta = DerSequence().decode(parameters)

    extension_field = GF(2 ** m)

    left = identity_matrix(extension_field, k)
    right = decode(key, MatrixSpace(extension_field, k, n - k))

    g = left.augment(right)

    return PublicKey(g, delta)


def _random_gabidulin_code(m, n, k):
    field = GF(2 ** m)
    generator = random_rank_vector(VectorSpace(field, n), n)

    return GabidulinCode(field, n, k, evaluation_points=generator.list())


def _select_parameters(security_level):
    parameters = {
        128: (64, 58, 28, 3),
        192: (96, 62, 32, 3),
        256: (128, 64, 28, 3),
    }

    if security_level not in parameters:
        raise ValueError("invalid security level")

    return parameters[security_level]
