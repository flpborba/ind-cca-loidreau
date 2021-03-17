from abc import ABC

from Crypto.Hash import SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256


class HashFunction(ABC):
    def __call__(self, data):
        NotImplemented

    def digest_size(self):
        NotImplemented


class ExtendableOutputFunction(ABC):
    def __call__(self, data, size):
        NotImplemented


class SHA3:
    _IMPL = {128: SHA3_256, 192: SHA3_384, 256: SHA3_512}

    def __init__(self, security_level):
        self._impl = self._IMPL.get(security_level)

        if self._impl is None:
            raise ValueError(f"invalid security parameter {security_level}")

    def __call__(self, data):
        return self._impl.new(data).digest()

    def digest_size(self):
        return self._impl.digest_size


class SHAKE:
    _IMPL = {128: SHAKE128, 192: SHAKE256, 256: SHAKE256}

    def __init__(self, security_level):
        self._impl = self._IMPL.get(security_level)

        if self._impl is None:
            raise ValueError(f"invalid security parameter {security_level}")

    def __call__(self, data, size):
        return self._impl.new(data).read(size)
