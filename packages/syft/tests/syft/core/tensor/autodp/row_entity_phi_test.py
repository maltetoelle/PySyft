# stdlib
from random import uniform

# third party
import numpy as np
import pytest

# syft absolute
from syft import deserialize
from syft import serialize
from syft.core.adp.entity import Entity
from syft.core.tensor.autodp.row_entity_phi import RowEntityPhiTensor
from syft.core.tensor.tensor import Tensor

gonzalo = Entity(name="Gonzalo")


@pytest.fixture(scope="function")
def x() -> Tensor:
    x = Tensor(np.array([[1, 2, 3], [4, 5, 6]]))
    x = x.private(min_val=-1, max_val=7, entity=gonzalo)
    return x


@pytest.fixture(scope="function")
def y() -> Tensor:
    y = Tensor(np.array([[-1, -2, -3], [-4, -5, -6]]))
    y = y.private(min_val=-7, max_val=1, entity=gonzalo)
    return y


ent = Entity(name="test")
ent2 = Entity(name="test2")

child1 = np.random.uniform(-2, 3, 5).tolist()
child2 = np.random.uniform(4, 6, 5).tolist()

tensor1 = RowEntityPhiTensor(
    rows=child1, check_shape=False 
)
# different data
tensor2 = RowEntityPhiTensor(
    rows=child2, check_shape=False 
)

simple_type1 = uniform(-6, -4)
simple_type2 = uniform(4, 6)


def test_le() -> None:

    assert tensor1.__le__(tensor2)
    assert tensor1.__le__(tensor1)
    assert tensor2.__le__(tensor1), "tensor2 is not less than or equal to tensor1"
    assert tensor1.__le__(
        simple_type1
    ), "tensor1 is not less than or equal to simple_type1"
    assert tensor1.__le__(simple_type2)


def test_ge() -> None:

    assert tensor1.__ge__(tensor2), "tensor1 is not greater than or equal to tensor2"
    assert tensor1.__ge__(tensor1)
    assert tensor2.__ge__(tensor1)
    assert tensor1.__ge__(simple_type1)
    assert tensor1.__ge__(
        simple_type2
    ), "tensor1 is not greater than or equal to simple_type1"


def test_lt() -> None:

    assert tensor1.__lt__(tensor2)
    assert tensor1.__lt__(tensor1), "tensor1 is not less than tensor1, they are both equal"
    assert tensor2.__lt__(tensor1), "tensor2 is not less than tensor1"
    assert tensor1.__lt__(simple_type1), "tensor1 is not less than simple_type1"
    assert tensor1.__lt__(simple_type2)


def test_gt() -> None:

    assert tensor1.__gt__(
        tensor2
    ), "tensor1 is not greater than tensor2"
    assert tensor1.__gt__(tensor1), "tensor1 is not greater than tensor1, they are both equal"
    assert tensor2.__gt__(tensor1)
    assert tensor1.__gt__(simple_type1)
    assert tensor1.__gt__(simple_type2), "tensor1 is not greater than simple_type1"
