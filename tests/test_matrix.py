from contextlib import nullcontext

import sage.all  # noqa: F401 (required by sage)
from pytest import mark, param, raises
from sage.rings.finite_rings.finite_field_constructor import GF

from loidreau.matrix import random_invertible_subpace_matrix


@mark.parametrize(
    "field, subspace_dimension, order, context",
    [
        (GF(2 ** 2), 2, 2, nullcontext()),
        (GF(2 ** 2), 2, 3, nullcontext()),
        (GF(2 ** 2), 2, 4, nullcontext()),
        (GF(2 ** 4), 2, 2, nullcontext()),
        (GF(2 ** 4), 4, 6, nullcontext()),
        param(GF(2 ** 2), 3, 3, raises(ValueError)),
        param(GF(2 ** 4), 6, 4, raises(ValueError)),
    ],
)
def test_random_invertible_subspace_matrix(
    field,
    subspace_dimension,
    order,
    context,
):
    with context:
        m = random_invertible_subpace_matrix(field, subspace_dimension, order)
        assert m.rank() == order
