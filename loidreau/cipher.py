from abc import ABC

import sage.all  # noqa: F401 (required by sage)
from Crypto.Util.strxor import strxor
from sage.coding.decoder import DecodingError
from sage.coding.linear_rank_metric import rank_weight
from sage.modules.free_module import FreeModule_ambient_field as VectorSpace
from sage.rings.finite_rings.finite_field_constructor import GF

from .io import BYTE_SIZE, decode, encode
from .matrix import random_rank_vector


class Cipher(ABC):
    def plaintext_len(self):
        message_len = self._key.m() * self._key.k() // BYTE_SIZE
        return message_len - self._hash.digest_size()

    def ciphertext_len(self):
        return self._key.m() * self._key.n() // BYTE_SIZE

    def _message_space(self):
        return VectorSpace(self._extension_field(), self._key.k())

    def _codeword_space(self):
        return VectorSpace(self._extension_field(), self._key.n())

    def _extension_field(self):
        return GF(2 ** self._key.m())

    def _decoding_capacity(self):
        return (self._key.n() - self._key.k()) // (2 * self._key.delta())


class Enc(Cipher):
    def __init__(self, public_key, hash_algorithm, xof_algorithm):
        self._key = public_key
        self._hash = hash_algorithm
        self._xof = xof_algorithm

    def __call__(self, plaintext):
        rank = self._decoding_capacity()
        error = encode(random_rank_vector(self._codeword_space(), rank))

        verifier_hash = self._hash(error + plaintext)
        extended_plaintext = plaintext + verifier_hash

        error_hash = self._xof(error, len(extended_plaintext))

        message = strxor(extended_plaintext, error_hash)
        message = decode(message, self._message_space())

        codeword = encode(message * self._key.g())
        ciphertext = strxor(codeword, error)

        return ciphertext


class Dec(Cipher):
    def __init__(self, secret_key, hash_algorithm, xof_algorithm):
        self._key = secret_key
        self._hash = hash_algorithm
        self._xof = xof_algorithm

    def __call__(self, ciphertext):
        received_word = decode(ciphertext, self._codeword_space())

        codeword = self._key.c().decode_to_code(received_word * self._key.p())
        message = encode(self._key.c().unencode(codeword) * self._key.s())

        error_vector = received_word + codeword * self._key.p().inverse()

        error = encode(error_vector)
        error_hash = self._xof(error, len(message))

        extended_plaintext = strxor(message, error_hash)
        plaintext, verifier_hash = self._extract_hash(extended_plaintext)

        hash_verified = verifier_hash == self._hash(error + plaintext)
        rank_verified = rank_weight(error_vector) == self._decoding_capacity()

        if not hash_verified and not rank_verified:
            raise DecodingError()

        return plaintext

    def _extract_hash(self, extended_plaintext):
        index = self.plaintext_len()
        return extended_plaintext[:index], extended_plaintext[index:]
