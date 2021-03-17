from math import ceil

import sage.all  # noqa: F401 (required by sage)
from more_itertools import grouper
from sage.matrix.constructor import matrix
from sage.matrix.matrix_space import MatrixSpace
from sage.modules.free_module import FreeModule_ambient_field as VectorSpace
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_base import FiniteField
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.structure.element import FieldElement, Matrix, Vector

BYTE_SIZE = 8


def encode(object):
    if isinstance(object, FieldElement):
        return encode_elem(object)

    elif isinstance(object, Vector) or isinstance(object, Matrix):
        return encode_elem_list(object.list())

    else:
        raise ValueError(f"unsupported element type: {type(object)}")


def decode(data, space):
    if isinstance(space, FiniteField):
        return decode_elem(data, space)

    elif isinstance(space, VectorSpace):
        elems = decode_elem_list(data, space.base_ring())
        return vector(elems)

    elif isinstance(space, MatrixSpace):
        elems = decode_elem_list(data, space.base_ring())
        return matrix(space=space, entries=elems)

    else:
        raise ValueError(f"unsupported space: {type(space)}")


def encode_elem_list(elems):
    return b"".join(encode_elem(e) for e in elems)


def decode_elem_list(data, field):
    bytes_per_elem = ceil(field.degree() / BYTE_SIZE)
    chunks = grouper(data, bytes_per_elem)

    return [decode_elem(bytes(c), field) for c in chunks]


def encode_elem(elem):
    field = elem.parent()

    if field.characteristic() != 2:
        raise ValueError("the element is not in a field of characteristic two")

    if field is GF(2):
        return b"\x00" if elem == 0 else b"\x01"

    num_bytes = ceil(field.degree() / BYTE_SIZE)
    return elem.integer_representation().to_bytes(num_bytes, "big")


def decode_elem(data, field=None):
    if field is None:
        deg = len(data) * BYTE_SIZE
        field = GF(2 ** deg)

    if field.characteristic() != 2:
        raise ValueError("finite field has not characteristic two")

    if field is GF(2):
        return field(0) if data == b"\x00" else field(1)

    return field.fetch_int(int.from_bytes(data, "big"))
