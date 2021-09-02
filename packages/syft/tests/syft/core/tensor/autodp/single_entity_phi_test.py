# stdlib
from random import uniform

# third party
import numpy as np
import pytest

# syft absolute
from syft import deserialize
from syft import serialize
from syft.core.adp.entity import Entity
from syft.core.tensor.autodp.single_entity_phi import SingleEntityPhiTensor
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

child1 = np.random.uniform(-2, 3, 5)
child2 = np.random.uniform(4, 6, 5)

tensor1 = SingleEntityPhiTensor(
    child=child1, entity=ent, max_vals=np.amax(child1), min_vals=np.amin(child1)
)
# same entity, same data
tensor2 = SingleEntityPhiTensor(
    child=child1, entity=ent, max_vals=np.amax(child1), min_vals=np.amin(child1)
)
# same entity, different data
tensor3 = SingleEntityPhiTensor(
    child=child2, entity=ent, max_vals=np.amax(child2), min_vals=np.amin(child2)
)
# different entity, same data
tensor4 = SingleEntityPhiTensor(
    child=child1, entity=ent2, max_vals=np.amax(child1), min_vals=np.amin(child1)
)
# different entity, different data
tensor5 = SingleEntityPhiTensor(
    child=child2, entity=ent2, max_vals=np.amax(child2), min_vals=np.amin(child2)
)

simple_type1 = uniform(-6, -4)
simple_type2 = uniform(4, 6)


def test_le() -> None:

    assert tensor1.__le__(tensor2)
    assert tensor3.__le__(tensor1), "tensor3 is not less than or equal to tensor1"
    assert tensor1.__le__(tensor4) == NotImplemented
    assert tensor1.__le__(tensor5) == NotImplemented
    assert tensor1.__le__(
        simple_type1
    ), "tensor1 is not less than or equal to simple_type1"
    assert tensor1.__le__(simple_type2)


def test_ge() -> None:

    assert tensor1.__ge__(tensor2)
    assert tensor1.__ge__(tensor3), "tensor1 is not greater than or equal to tensor3"
    assert tensor1.__ge__(tensor4) == NotImplemented
    assert tensor1.__ge__(tensor5) == NotImplemented
    assert tensor1.__ge__(simple_type1)
    assert tensor1.__ge__(
        simple_type2
    ), "tensor1 is not greater than or equal to simple_type1"


def test_lt() -> None:

    assert tensor1.__lt__(
        tensor2
    ), "tensor1 is not less than tensor2, they are both equal"
    assert tensor1.__lt__(tensor3)
    assert tensor1.__lt__(tensor4) == NotImplemented
    assert tensor1.__lt__(tensor5) == NotImplemented
    assert tensor1.__lt__(simple_type1), "tensor1 is not less than simple_type1"
    assert tensor1.__lt__(simple_type2)


def test_gt() -> None:

    assert tensor1.__gt__(
        tensor2
    ), "tensor1 is not greater than tensor2, they are both equal"
    assert tensor1.__gt__(tensor3), "tensor1 is not greater than tensor3"
    assert tensor1.__gt__(tensor4) == NotImplemented
    assert tensor1.__gt__(tensor5) == NotImplemented
    assert tensor1.__gt__(simple_type1)
    assert tensor1.__gt__(simple_type2), "tensor1 is not greater than simple_type1"


#
# ######################### ADD ############################
#
# MADHAVA: this needs fixing
@pytest.mark.xfail
def test_add(x: Tensor) -> None:
    z = x + x
    assert isinstance(z, Tensor), "Add: Result is not a Tensor"
    assert (
        z.child.min_vals == 2 * x.child.min_vals
    ).all(), "(Add, Minval) Result is not correct"
    assert (
        z.child.max_vals == 2 * x.child.max_vals
    ).all(), "(Add, Maxval) Result is not correct"


# MADHAVA: this needs fixing
@pytest.mark.xfail
def test_single_entity_phi_tensor_serde(x: Tensor) -> None:

    blob = serialize(x.child)
    x2 = deserialize(blob)

    assert (x.child.min_vals == x2.min_vals).all()
    assert (x.child.max_vals == x2.max_vals).all()


# def test_add(x,y):
#     z = x+y
#     assert isinstance(z, Tensor), "Add: Result is not a Tensor"
#     assert z.child.min_vals == x.child.min_vals + y.child.min_vals, "(Add, Minval) Result is not correct"
#     assert z.child.max_vals == x.child.max_vals + y.child.max_vals, "(Add, Maxval) Result is not correct"
#
# ######################### SUB ############################
#
# def test_sub(x):
#     z=x-x
#     assert isinstance(z, Tensor), "Sub: Result is not a Tensor"
#     assert z.child.min_vals == 0 * x.child.min_vals, "(Sub, Minval) Result is not correct"
#     assert z.child.max_vals == 0 * x.child.max_vals, "(Sub, Maxval) Result is not correct"
#
# def test_sub(x,y):
#     z=x-y
#     assert isinstance(z, Tensor), "Sub: Result is not a Tensor"
#     assert z.child.min_vals == x.child.min_vals - y.child.min_vals, "(Sub, Minval) Result is not correct"
#     assert z.child.max_vals == x.child.max_vals - y.child.max_vals, "(Sub, Maxval) Result is not correct"
#
# ######################### MUL ############################
#
# def test_mul(x):
#     z = x*x
#     assert isinstance(z, Tensor), "Mul: Result is not a Tensor"
#     assert z.child.min_vals == x.child.min_vals ** 2, "(Mul, Minval) Result is not correct"
#     assert z.child.max_vals == x.child.max_vals ** 2, "(Mul, Maxval) Result is not correct"
#
# def test_mul(x,y):
#     z = x*y
#     assert isinstance(z, Tensor), "Mul: Result is not a Tensor"
#     assert z.child.min_vals == x.child.min_vals ** 2, "(Mul, Minval) Result is not correct"
#     assert z.child.max_vals == x.child.max_vals ** 2, "(Mul, Maxval) Result is not correct"
