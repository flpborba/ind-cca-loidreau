"""This module provides facilities to generate random matrices and vectors."""

import sage.all  # noqa: F401 (required by sage)
from sage.coding.linear_rank_metric import from_matrix_representation
from sage.matrix.constructor import matrix
from sage.matrix.matrix_space import MatrixSpace
from sage.matrix.special import random_echelonizable_matrix
from sage.modules.free_module import VectorSpace
from sage.modules.free_module_element import vector
from sage.rings.finite_rings.finite_field_constructor import GF


def random_invertible_matrix(field, order):
    """Generate a random invertible matrix over the given finite field.

    Parameters
    ----------
    field : FiniteField
        Finite field of matrix elements.
    order : int
        Matrix order.

    Returns
    -------
    Matrix
    """
    space = MatrixSpace(field, order, order)
    return random_echelonizable_matrix(space, order, max_tries=None)


def random_invertible_subpace_matrix(field, subspace_dimension, order):
    """Generate a random invertible matrix over the given finite field whose
    elements belong to a random vector subspace of a certain dimension.

    Parameters
    ----------
    field : FiniteField
        Finite field of matrix elements.
    subspace_dimension : int
        Dimension of the vector subspace of elements.
    order : int
        Matrix order.

    Returns
    -------
    Matrix

    Raises
    ------
    ValueError
        Error raised when the field degree is less than the vector subspace
        dimension.
    """
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
    """Generate a random vector with the given rank over GF(2).

    Parameters
    ----------
    vector_space :
        Vector space in which generate the vector.
    rank : int
        Rank of the vector.

    Returns
    -------
    Vector
    """
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
    """Create a random linear map between two vector spaces over GF(2).

    Parameters
    ----------
    v : VectorSpace
        Vector space to map from.
    w : VectorSpace
        Vector space to map to.

    Returns
    -------
    A random linear map from `v` to `w`.
    """
    matrix_space = MatrixSpace(GF(2), v.degree(), w.degree())
    m = random_echelonizable_matrix(matrix_space, v.degree(), max_tries=None)

    return m.linear_combination_of_rows
