"""This module provides abstract classes from which objects for hash and
extendable-output (XOF) functions should inherit.

This module also provides some concrete implementation for popular hash and
XOF algorithms.

Classes
-------
HashFunction:
    Abstract class for hash functions.
ExtendableOutputFunction:
    Abstract class for extendable-output functions.
SHA3:
    Implementation of SHA-3 hash functions.
SHAKE:
    Implementation of SHAKE extendable-output functions.
"""

from abc import ABC

from Crypto.Hash import SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256


class HashFunction(ABC):
    """Abstract class for hash functions.

    Functions used with this cryptosystem shall implement the interface
    defined in this class.
    """

    def __call__(self, message):
        """Compute the message digest.

        Parameters
        ----------
        message : bytes
            Input message.
        """
        NotImplemented

    def digest_size(self):
        """Return the digest size in bytes.

        Returns
        -------
        int
            Size of the digest.
        """
        NotImplemented


class ExtendableOutputFunction(ABC):
    """Abstract class for extendable-output functions.

    Functions used with this cryptosystem shall implement the interface
    defined in this class.
    """

    def __call__(self, message, size):
        """Compute a message digest of the given size.

        Parameters
        ----------
        message : bytes
            Input message.
        size : int
            Size of the resulting digest in bytes.
        """
        NotImplemented


class SHA3:
    """Implementation of SHA-3 hash functions.

    Internally, this class uses one of the SHA3 implementations from
    PyCryptodome, depending on the security level.
    """

    _IMPL = {128: SHA3_256, 192: SHA3_384, 256: SHA3_512}

    def __init__(self, security_level):
        """Create a suitable SHA-3 hash function to use with the cryptosystem.

        Parameters
        ----------
        security_level : {128, 192, 256}
            Level of security desired.

        Raises
        ------
        ValueError
            If the security level is not a suitable values to use with the
            cryptosystem.
        """
        self._impl = self._IMPL.get(security_level)

        if self._impl is None:
            raise ValueError(f"invalid security parameter {security_level}")

    def __call__(self, data):
        return self._impl.new(data).digest()

    def digest_size(self):
        return self._impl.digest_size


class SHAKE:
    """Implementation of SHAKE extendable-output functions.

    Internally, this class uses one of the SHA3 implementations from
    PyCryptodome, depending on the security level.
    """

    _IMPL = {128: SHAKE128, 192: SHAKE256, 256: SHAKE256}

    def __init__(self, security_level):
        """Create a suitable SHA-3 extendable-output function to use with the
        cryptosystem.

        Parameters
        ----------
        security_level : {128, 192, 256}
            Level of security desired.

        Raises
        ------
        ValueError
            If the security level is not a suitable values to use with the
            cryptosystem.
        """
        self._impl = self._IMPL.get(security_level)

        if self._impl is None:
            raise ValueError(f"invalid security parameter {security_level}")

    def __call__(self, data, size):
        return self._impl.new(data).read(size)
