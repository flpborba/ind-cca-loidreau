"""This module provides facilities to generate, import and export private and
public keys used in the cryptosystem.

Classes
-------
Key
    Common base for private and public keys.
SecretKey
    A private key.
Dec
    A public key.
"""

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
    """Common base for public and secret keys."""

    def m(self):
        """Return the underlying code extension field.

        Returns
        -------
        int
        """
        NotImplemented

    def n(self):
        """Return the underlying code length.

        Returns
        -------
        int
        """
        NotImplemented

    def k(self):
        """Return the underlying code dimension.

        Returns
        -------
        int
        """
        NotImplemented

    def delta(self):
        """Return the subspace dimension used for key generation.

        Returns
        -------
        int
        """
        NotImplemented


class SecretKey(Key):
    """Secret key of the encryption scheme."""

    def __init__(self, c, s, p, delta):
        """Create a new secret key.

        Parameters
        ----------
        c : GabidulinCode
            An [n, k] Gabidulin code over GF(2 ** m).
        s : Matrix
            A non-singular matrix of order k over GF(2 ** m).
        p : Matrix
            A non-singular matrix of order n with entries in a in vector
            subspace of GF(2 ** m).
        dim: int
            The dimension of the vector subspace the elements of `p` belong.
        """
        self._c = c
        self._s = s
        self._p = p
        self._d = delta

    def public_key(self):
        """Derive the corresponding public key.

        Returns
        -------
        PublicKey
        """
        g = self._s.inverse() * self._c.generator_matrix() * self._p.inverse()
        return PublicKey(g, self._d)

    def export_pem(self):
        """Export this key in PEM format.

        This method first encoded this key in DER format using `export_der`
        and then encodes the resulting bytes in PEM format.

        Returns
        -------
        str
            The PEM-encoded key.

        See Also
        --------
        export_der
        """
        der_encoded = self.export_der()
        marker = "PRIVATE KEY"

        return PEM.encode(der_encoded, marker)

    def export_der(self):
        """Export this key in DER format.

        The ASN.1 structure of a secret key is the following:

            PrivateKey ::= SEQUENCE {
                generator       OCTET STRING
                rowScrambler    OCTET STRING
                columnScrambler OCTET STRING
                parameters      Parameters
            }

            Parameters := SEQUENCE {
                extDegree   INTEGER
                codeLength  INTEGER
                codeDim     INTEGER
                subspaceDim INTEGER
            }

        Returns
        -------
        bytes
        """
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
        """Return the secret code.

        Returns
        -------
        GabidulinCode
        """
        return self._c

    def s(self):
        """Return the row scrambler matrix.

        Returns
        -------
        Matrix
        """
        return self._s

    def p(self):
        """Return the column scrambler or permutation matrix.

        Returns
        -------
        Matrix
        """
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
    """Public key of the encryption scheme."""

    def __init__(self, g, delta):
        """Create a PublicKey.

        Parameters
        ----------
        g : Matrix
            The public code generator matrix.
        """
        self._g = g
        self._d = delta

    def export_pem(self):
        """Export this key in PEM format.

        This method first encoded this key in DER format using `export_der`
        and then encodes the resulting bytes in PEM format.

        Returns
        -------
        str

        See Also
        --------
        export_der
        """
        der_encoded = self.export_der()
        marker = "PUBLIC KEY"

        return PEM.encode(der_encoded, marker)

    def export_der(self):
        """Export this key in DER format.

        The ASN.1 structure of a public key is the following:

            PublicKey ::= SEQUENCE {
                publicGenerator BIT STRING
                parameters      Parameters
            }

            Parameters := SEQUENCE {
                extDegree       INTEGER
                codeLength      INTEGER
                codeDim         INTEGER
                subspaceDim     INTEGER
            }

        Returns
        -------
        bytes
        """
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
        """Returns the public code generator matrix.

        Returns
        -------
        Matrix
        """
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
    """Generate a new secret key.

    Parameters
    ----------
    security_level: int
        The required security level the key must provide.

    Returns
    -------
    SecretKey
    """
    m, n, k, delta = _select_parameters(security_level)

    c = _random_gabidulin_code(m, n, k)
    s = random_invertible_matrix(GF(2 ** m), k)
    p = random_invertible_subpace_matrix(GF(2 ** m), delta, n)

    t = s * c.generator_matrix() * p.inverse()
    s = s.inverse() * t.submatrix(ncols=k)

    return SecretKey(c, s, p, delta)


def import_secret_pem(data):
    """Import a PEM-encoded secret key.

    Parameters
    ----------
    data : bytes
        The key encoded in PEM format.

    Returns
    -------
    SecretKey
    """
    der_encoded, marker, _ = PEM.decode(data)

    if marker != "PRIVATE KEY":
        raise ValueError("invalid PEM-encoded private key")

    return import_secret_der(der_encoded)


def import_secret_der(data):
    """Import a DER-encoded secret key.

    Parameters
    ----------
    data : bytes
        The key encoded in DER format.

    Returns
    -------
    SecretKey
    """
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
    """Import a PEM-encoded public key.

    Parameters
    ----------
    data : bytes
        The key encoded in PEM format.

    Returns
    -------
    PublicKey
    """
    der_encoded, marker, _ = PEM.decode(data)

    if marker != "PUBLIC KEY":
        raise ValueError("invalid PEM-encoded public key")

    return import_public_der(der_encoded)


def import_public_der(data):
    """Import a DER-encoded public key.

    Parameters
    ----------
    data : bytes
        The key encoded in DER format.

    Returns
    -------
    PublicKey
    """
    key, parameters = DerSequence().decode(data)

    key = DerBitString().decode(key).payload[1:]
    m, n, k, delta = DerSequence().decode(parameters)

    extension_field = GF(2 ** m)

    left = identity_matrix(extension_field, k)
    right = decode(key, MatrixSpace(extension_field, k, n - k))

    g = left.augment(right)

    return PublicKey(g, delta)


def _random_gabidulin_code(m, n, k):
    """Generate a random Gabidulin code.

    Parameters
    ----------
    m : int
        Degree of the field extension.
    n : int
        Code length.
    k : int
        Code dimension.

    Returns
    -------
    GabidulinCode
    """
    field = GF(2 ** m)
    generator = random_rank_vector(VectorSpace(field, n), n)

    return GabidulinCode(field, n, k, evaluation_points=generator.list())


def _select_parameters(security_level):
    """Select the security parameters for key generation.

    Parameters
    ----------
    security_level : int {128, 192, 256}
        The required security level.

    Returns
    -------
    Tuple[int, int, int, int]
        The security parameters m, n, k, and delta.

    Raises
    ------
    ValueError
        If `security_level` is not in the available choices.
    """
    parameters = {
        128: (64, 58, 28, 3),
        192: (96, 62, 32, 3),
        256: (128, 64, 28, 3),
    }

    if security_level not in parameters:
        raise ValueError("invalid security level")

    return parameters[security_level]
