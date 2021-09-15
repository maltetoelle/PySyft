# future
from __future__ import annotations

# stdlib
import functools
from functools import lru_cache
import operator
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

# third party
from google.protobuf.reflection import GeneratedProtocolMessageType
import numpy as np
import torch

# syft absolute
from syft.core.common.serde.deserialize import _deserialize as deserialize
from syft.core.common.serde.serializable import Serializable
from syft.core.common.serde.serializable import bind_protobuf
from syft.core.common.serde.serialize import _serialize as serialize
from syft.core.tensor.passthrough import PassthroughTensor
from syft.proto.core.tensor.smpc.share_tensor_pb2 import ShareTensor as ShareTensor_PB

METHODS_FORWARD_ALL_SHARES = {
    "repeat",
    "copy",
    "diagonal",
    "flatten",
    "transpose",
    "partition",
    "resize",
    "ravel",
    "compress",
    "reshape",
    "squeeze",
    "swapaxes",
}
INPLACE_OPS = {
    "resize",
}
# relative
from .party import Party


@bind_protobuf
class ShareTensor(PassthroughTensor, Serializable):
    __slots__ = (
        "rank",
        "ring_size",
        "parties_info",  # parties info (email, password, port)
        "clients",  # clients connections
        "min_value",
        "max_value",
        "generator_przs",
        # Only ShareTensors with seed_przs could be sent over the wire
        "seed_przs",
    )

    def __init__(
        self,
        rank: int,
        parties_info: List[Party],
        seed_przs: int,
        clients: List[Any] = None,
        ring_size: int = 2 ** 32,  # TODO: This needs to be changed to 2^64
        value: Optional[Any] = None,
        init_clients: bool = True,
    ) -> None:
        self.rank = rank
        self.ring_size = ring_size
        self.nr_parties = len(parties_info)
        self.parties_info = parties_info
        if clients is not None:
            self.clients = clients
        elif init_clients:
            # syft absolute
            import syft as sy

            self.clients = [
                sy.login(
                    url=party_info.url,
                    email=party_info.email,
                    password=party_info.passwd,
                    port=party_info.port,
                )
                for party_info in parties_info
            ]

        self.min_value, self.max_value = ShareTensor.compute_min_max_from_ring(
            self.ring_size
        )

        # This should be set only in the deserializer
        self.generator_przs = None
        self.seed_przs = seed_przs
        super().__init__(value)

    def __getitem__(self, item: Union[str, int, slice]) -> ShareTensor:
        return ShareTensor(
            rank=self.rank,
            parties=self.parties,
            ring_size=self.ring_size,
            value=self.child[item],
        )

    def copy_tensor(self) -> ShareTensor:
        return ShareTensor(
            rank=self.rank,
            nr_parties=self.nr_parties,
            ring_size=self.ring_size,
            seed_przs=self.seed_przs,
        )

    @staticmethod
    @lru_cache(32)
    def compute_min_max_from_ring(ring_size: int = 2 ** 32) -> Tuple[int, int]:
        min_value = (-ring_size) // 2
        max_value = (ring_size - 1) // 2
        return min_value, max_value

    """ TODO: Remove this -- we would use generate_przs since the scenario we are testing is that
    the secret is remotly
    @staticmethod
    def generate_shares(secret, nr_shares, ring_size=2 ** 64):
        from .fixed_precision_tensor import FixedPrecisionTensor

        if not isinstance(secret, (int, FixedPrecisionTensor)):
            secret = FixedPrecisionTensor(value=secret)

        shape = secret.shape
        min_value, max_value = ShareTensor.compute_min_max_from_ring(ring_size)

        generator_shares = np.random.default_rng()

        random_shares = []
        for i in range(nr_shares):
            random_value = generator_shares.integers(
                low=min_value, high=max_value, size=shape
            )
            fpt_value = FixedPrecisionTensor(value=random_value)
            random_shares.append(fpt_value)

        shares_fpt = []
        for i in range(nr_shares):
            if i == 0:
                share = value = random_shares[i]
            elif i < nr_shares - 1:
                share = random_shares[i] - random_shares[i - 1]
            else:
                share = secret - random_shares[i - 1]

            shares_fpt.append(share)

        # Add the ShareTensor class between them
        shares = []
        for rank, share_fpt in enumerate(shares_fpt):
            share_fpt.child = ShareTensor(rank=rank, value=share_fpt.child)
            shares.append(share_fpt)

        return shares
    """

    @staticmethod
    def generate_przs(
        value: Optional[Any],
        shape: Tuple[int],
        rank: int,
        parties_info: List[Party],
        seed_przs: Optional[int] = None,
        generator_przs: Optional[Any] = None,
    ) -> "ShareTensor":

        nr_parties = len(parties_info)

        # syft absolute
        from syft.core.tensor.tensor import Tensor

        if (seed_przs is None) == (generator_przs is None):
            raise ValueError("Only seed_przs or generator should be populated")

        if value is None:
            value = Tensor(np.zeros(shape, dtype=np.int32))  # TODO: change to np.int64

        # TODO: Sending the seed and having each party generate the shares is not safe
        # Since the parties would know some of the other parties shares (this might not impose a risk
        # when shares are not sent between parties -- like private addition/subtraction, but it might
        # impose for multiplication
        # The secret holder should generate the shares and send them to the other parties
        if generator_przs:
            generator_shares = generator_przs
        else:
            generator_shares = np.random.default_rng(seed_przs)

        if isinstance(value, ShareTensor):
            share = value
        elif isinstance(value.child, ShareTensor):
            share = value.child
        else:
            share = ShareTensor(
                value=value.child,
                rank=rank,
                parties_info=parties_info,
                seed_przs=None,
                init_clients=False,
            )

        share.generator_przs = generator_shares
        shares = [
            generator_shares.integers(
                low=share.min_value, high=share.max_value, size=shape
            )
            for _ in parties_info
        ]
        share.child += shares[rank] - shares[(rank + 1) % nr_parties]

        return share

    @staticmethod
    def generate_przs_on_dp_tensor(
        value: Optional[Any],
        shape: Tuple[int],
        rank: int,
        parties_info: List[Party],
        seed_przs: int,
        share_wrapper: Any,
    ) -> PassthroughTensor:

        if value is not None:
            share = ShareTensor.generate_przs(
                value=value.child,
                shape=shape,
                rank=rank,
                parties_info=parties_info,
                seed_przs=seed_przs,
            )
        else:
            share = ShareTensor.generate_przs(
                value=value,
                shape=shape,
                rank=rank,
                parties_info=parties_info,
                seed_przs=seed_przs,
            )

        share_wrapper.child.child = share

        return share_wrapper

    @staticmethod
    def sanity_check(
        share: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    ) -> None:
        """Check type for share

        Args:
            share (Union[int, float, ShareTensor, np.ndarray, torch.Tensor]): value to check

        Raises:
            ValueError: if type is not supported
        """
        if isinstance(share, float):
            raise ValueError("Type float not supported yet!")

        if isinstance(share, np.ndarray) and not np.issubdtype(share.dtype, np.integer):
            raise ValueError(f"NPArray should have type int, but found {share.dtype}")

        if isinstance(share, torch.Tensor) and torch.is_floating_point(share):
            raise ValueError("Torch tensor should have type int, but found float")

    def apply_function(
        self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"], op_str: str
    ) -> "ShareTensor":
        """Apply a given operation.

        Args:
            y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): tensor to apply the operator.
            op_str (str): Operator.

        Returns:
            ShareTensor: Result of the operation.
        """

        op = getattr(operator, op_str)
        if isinstance(y, ShareTensor):
            value = op(self.child, y.child)
        else:
            # TODO: Converting y to numpy because doing "numpy op torch tensor" raises exception
            value = op(self.child, np.array(y, np.int32))  # TODO: change to np.int64

        res = self.copy_tensor()
        res.child = value
        return res

    def add(
        self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    ) -> "ShareTensor":
        """Apply the "add" operation between "self" and "y".

        Args:
            y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): self + y

        Returns:
            ShareTensor. Result of the operation.
        """

        ShareTensor.sanity_check(y)

        new_share = self.apply_function(y, "add")

        return new_share

    def sub(
        self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    ) -> "ShareTensor":
        """Apply the "sub" operation between "self" and "y".

        Args:
            y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): self - y

        Returns:
            ShareTensor. Result of the operation.
        """

        ShareTensor.sanity_check(y)
        new_share = self.apply_function(y, "sub")
        return new_share

    def rsub(
        self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    ) -> "ShareTensor":
        """Apply the "rsub" operation between "self" and "y"

        Args:
            y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): y - self

        Returns:
            ShareTensor. Result of the operation.
        """

        ShareTensor.sanity_check(y)
        new_self = self.mul(-1)
        new_share = new_self.apply_function(y, "add")
        return new_share

    def mul(
        self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    ) -> "ShareTensor":
        """Apply the "mul" operation between "self" and "y".

        Args:
            y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): self * y

        Returns:
            ShareTensor. Result of the operation.
        """

        if isinstance(y, ShareTensor):
            raise ValueError("Private mul not supported yet")

        ShareTensor.sanity_check(y)
        new_share = self.apply_function(y, "mul")
        return new_share

    def matmul(
        self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    ) -> "ShareTensor":
        """Apply the "matmul" operation between "self" and "y".

        Args:
            y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): self @ y.

        Returns:
            ShareTensor: Result of the operation.
        """
        ShareTensor.sanity_checks(y)
        new_share = self.apply_function(y, "matmul")
        return new_share

    def rmatmul(self, y: torch.Tensor) -> "ShareTensor":
        """Apply the "rmatmul" operation between "y" and "self".

        Args:
            y (torch.Tensor): y @ self

        Returns:
            ShareTensor. Result of the operation.
        """
        ShareTensor.sanity_checks(y)
        return y.matmul(self)

    # TRASK: commenting out because ShareTEnsor doesn't appear to have .session_uuid or .config
    # def div(
    #     self, y: Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]
    # ) -> "ShareTensor":
    #     """Apply the "div" operation between "self" and "y".
    #
    #     Args:
    #         y (Union[int, float, torch.Tensor, np.ndarray, "ShareTensor"]): Denominator.
    #
    #     Returns:
    #         ShareTensor: Result of the operation.
    #
    #     Raises:
    #         ValueError: If y is not an integer or LongTensor.
    #     """
    #     if not isinstance(y, (int, torch.LongTensor)):
    #         raise ValueError("Div works (for the moment) only with integers!")
    #
    #     res = ShareTensor(session_uuid=self.session_uuid, config=self.config)
    #     # res = self.apply_function(y, "floordiv")
    #     res.tensor = self.tensor // y
    #     return res

    @staticmethod
    def hook_method(__self: ShareTensor, method_name: str) -> Callable[..., Any]:
        """Hook a framework method.

        Args:
            method_name (str): method to hook

        Returns:
            A hooked method
        """

        def method_all_shares(
            _self: ShareTensor, *args: List[Any], **kwargs: Dict[Any, Any]
        ) -> Any:

            share = _self.child
            if method_name != "resize":
                method = getattr(share, method_name)
            else:
                # Should be modified to remove copy
                # https://stackoverflow.com/questions/23253144/numpy-the-array-doesnt-have-its-own-data
                share = share.copy()
                method = getattr(share, method_name)

            if method_name not in INPLACE_OPS:
                new_share = method(*args, **kwargs)
            else:
                method(*args, **kwargs)
                new_share = share

            res = ShareTensor(
                rank=_self.rank,
                nr_parties=_self.nr_parties,
                ring_size=_self.ring_size,
                value=new_share,
            )

            return res

        return functools.partial(method_all_shares, __self)

    def __getattribute__(self, attr_name: str) -> Any:

        if attr_name in METHODS_FORWARD_ALL_SHARES:
            return ShareTensor.hook_method(self, attr_name)

        return object.__getattribute__(self, attr_name)

    def _object2proto(self) -> ShareTensor_PB:
        proto_init_kwargs = {
            "rank": self.rank,
            "parties_info": [serialize(party) for party in self.parties_info],
            "seed_przs": self.seed_przs,
        }
        if isinstance(self.child, np.ndarray):
            proto_init_kwargs["array"] = serialize(self.child)
        elif isinstance(self.child, torch.Tensor):
            proto_init_kwargs["array"] = serialize(np.array(self.child))
        else:
            proto_init_kwargs["tensor"] = serialize(self.child)

        return ShareTensor_PB(**proto_init_kwargs)

    @staticmethod
    def _proto2object(proto: ShareTensor_PB) -> "ShareTensor":
        init_kwargs = {
            "rank": proto.rank,
            "parties_info": [deserialize(party) for party in proto.parties_info],
            "seed_przs": proto.seed_przs,
        }
        if proto.HasField("tensor"):
            init_kwargs["value"] = deserialize(proto.tensor)
        else:
            init_kwargs["value"] = deserialize(proto.array)

        res = ShareTensor(**init_kwargs)
        generator_przs = np.random.default_rng(proto.seed_przs)
        res.generator_przs = generator_przs
        return res

    @staticmethod
    def get_protobuf_schema() -> GeneratedProtocolMessageType:
        return ShareTensor_PB

    __add__ = add
    __radd__ = add
    __sub__ = sub
    __rsub__ = rsub
    __mul__ = mul
    __rmul__ = mul
    __matmul__ = matmul
    __rmatmul__ = rmatmul
