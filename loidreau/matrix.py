import sage.all  # noqa: F401 (required by sage)
from sage.coding.linear_rank_metric import from_matrix_representation
from sage.matrix.constructor import matrix
from sage.matrix.matrix_space import MatrixSpace
from sage.matrix.special import random_echelonizable_matrix
from sage.modules.free_module import VectorSpace
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF


def random_invertible_matrix(field, order):
    space = MatrixSpace(field, order, order)
    return random_echelonizable_matrix(space, order, max_tries=None)


def random_invertible_subpace_matrix(field, subspace_dimension, order):
    if field.degree() < subspace_dimension:
        error_msg = "field degree must be greater than or equal the subspace"
        "dimension"

        raise ValueError(error_msg)

    space = field.vector_space(map=False)
    subspace = VectorSpace(GF(2), subspace_dimension)

    subfield = GF(2 ** subspace_dimension)
    subfield_matrix = random_invertible_matrix(subfield, order)

    m = matrix(field, order)

    while m.rank() != order:
        linear_map = _random_linear_map(subspace, space)
        m = subfield_matrix.apply_map(lambda e: field(linear_map(vector(e))))

    return m


def random_rank_vector(vector_space, rank):
    field = vector_space.base_ring()

    matrix_space = MatrixSpace(
        GF(2),
        field.degree(),
        vector_space.degree(),
    )

    m = random_echelonizable_matrix(
        matrix_space,
        rank,
        max_tries=None,
    )

    return from_matrix_representation(m, field)


def _random_linear_map(v, w):
    matrix_space = MatrixSpace(GF(2), v.degree(), w.degree())
    m = random_echelonizable_matrix(matrix_space, v.degree(), max_tries=None)

    return m.linear_combination_of_rows
