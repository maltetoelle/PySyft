# stdlib
from typing import Any
from typing import Iterator
from typing import Union

# third party
from google.protobuf.reflection import GeneratedProtocolMessageType
import torch as th
from torch.utils.data import DataLoader
from torch.utils.data import Dataset

# syft relative
from ... import deserialize
from ... import serialize
from ...logger import traceback_and_raise
from ...proto.core.remote_dataloader.remote_dataset_pb2 import (
    RemoteDataLoader as RemoteDataLoader_PB,
)
from ...proto.core.remote_dataloader.remote_dataset_pb2 import (
    RemoteDataset as RemoteDataset_PB,
)
from ..common.serde.serializable import Serializable
from ..common.serde.serializable import bind_protobuf

DATA_TYPE_TORCH_TENSOR = "torch_tensor"

from typing import List, Tuple, Union
import torch as th
from torch.utils.data import Dataset


class CTDICOMDataset(Dataset):
    def __init__(self, ct_paths: List[str], ops_codes_paths: List[str]):
        self.ct_paths = ct_paths
        self.ops_codes_paths = ops_codes_paths

    def __getitem__(self, idx: Union[int, slice]) -> Tuple[th.Tensor, th.Tensor]:
        if type(idx) == slice:
            ct_vol = th.stack([th.load(self.ct_paths[i]) for i in range(idx.start, idx.stop)])
            ops_codes = th.stack([th.load(self.ops_codes_paths[i]) for i in range(idx.start, idx.stop)])
        else:
            ct_vol = th.load(self.ct_paths[idx])  # [None]
            ops_codes = th.load(self.ops_codes_paths[idx])  # [None]
        return ct_vol, ops_codes

    def __len__(self) -> int:
        return len(self.ct_paths)

@bind_protobuf
class RemoteDataset(Dataset, Serializable):
    def __init__(self, path: str, data_type: str = DATA_TYPE_TORCH_TENSOR):
        """
        Arguments:
            path: information about where to get the raw data, for example, a file path,
            or a directory path data_type: the type of data for example torch_tensor
        For now, it's should simply be a .pt file, which stores a Dataset object.
        """
        self.path = path
        self.data_type = data_type

    def load_dataset(self) -> None:
        """
        Load the real Dataset object on DO's machine.
        But for now, it's just simply calling torch.load on a .pt file.
        """
        if self.data_type == DATA_TYPE_TORCH_TENSOR:
            self.dataset = th.load(self.path)

    def __len__(self) -> int:
        return len(self.dataset)

    def __getitem__(self, key: Union[str, int, slice]) -> Union[th.Tensor]:
        return self.dataset[key]

    def __repr__(self) -> str:
        return f"{type(self)}: {self.data_type}"

    def _object2proto(self) -> RemoteDataset_PB:
        proto = RemoteDataset_PB()
        proto.path = self.path
        proto.data_type = self.data_type
        return proto

    @staticmethod
    def _proto2object(proto: Any) -> "RemoteDataset":
        return RemoteDataset(path=proto.path, data_type=proto.data_type)

    @staticmethod
    def get_protobuf_schema() -> GeneratedProtocolMessageType:
        return RemoteDataset_PB


@bind_protobuf
class RemoteDataLoader(Serializable):
    def __init__(self, remote_dataset: RemoteDataset, batch_size: int = 1):
        """
        TODO: now, only batch_size can be passed in by users, and it's used when create
        DataLoader object in self.create_dataloader. In future steps, more augmentations
        should be supported, like shuffle, sampler, collate_fn, etc.
        """
        self.remote_dataset = remote_dataset
        self.batch_size = batch_size

    def _object2proto(self) -> RemoteDataLoader_PB:
        proto = RemoteDataLoader_PB()
        proto.batch_size = self.batch_size
        proto.remote_dataset.CopyFrom(serialize(self.remote_dataset))
        return proto

    @staticmethod
    def _proto2object(proto: Any) -> "RemoteDataLoader":
        remote_dataset = deserialize(proto.remote_dataset)
        batch_size = proto.batch_size
        return RemoteDataLoader(remote_dataset=remote_dataset, batch_size=batch_size)

    @staticmethod
    def get_protobuf_schema() -> GeneratedProtocolMessageType:
        return RemoteDataLoader_PB

    def load_dataset(self) -> None:
        self.remote_dataset.load_dataset()

    def create_dataloader(self) -> None:
        if self.remote_dataset.data_type == DATA_TYPE_TORCH_TENSOR:
            dataset = getattr(self.remote_dataset, "dataset", None)
            self.dataloader = DataLoader(dataset=dataset, batch_size=self.batch_size)
        else:
            traceback_and_raise(
                ValueError(
                    "Cannot create a DataLoader for type: {self.remote_dataset.data_type}"
                )
            )

    def __len__(self) -> int:
        return len(self.dataloader)

    def __iter__(self) -> "Iterator":
        return iter(self.dataloader)
