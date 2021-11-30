# stdlib
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import Callable
from typing import Union
import json
import glob
import re
# from waiting import wait

# third party
from cryptography.fernet import Fernet
from eventlet import event
from eventlet.timeout import Timeout
import rsa
import socketio

# syft relative
from syft.core.common.message import SyftMessage
from syft.core.common.serde.serialize import _serialize
from syft.proto.core.node.common.metadata_pb2 import Metadata as Metadata_PB
from syft.grid.connections.ws_connection import WSConnection

def read_pub_key(path: str) -> bytes:
    with open(path, mode='rb') as public_file:
        key_data = public_file.read()
        public_key = rsa.PublicKey.load_pkcs1(key_data)
    return public_key

def read_priv_key(path: str) -> bytes:
    with open(path, mode='rb') as priv_file:
        key_data = priv_file.read()
        priv_key = rsa.PrivateKey.load_pkcs1(key_data)
    return priv_key

def decrypt_response(conn: Any, key: bytes, response: bytes) -> bytes:
    # priv_key_path = glob.glob(f"./ssh-keys/private_ds_*_{url.split('/')[-1]}.pem")[0]
    # priv_key = read_priv_key(priv_key_path)
    # key = rsa.decrypt(key, priv_key)
    fernet = Fernet(key)
    response = fernet.decrypt(response)  # [fernet.decrypt(r) for r in res[:-1]]
    response = response.decode().encode("ISO-8859-1")
    return response

def socket_wrapper(sio_ev: str, response_fn: Optional[Callable] = decrypt_response):
    def _socket_wrapper(f: Callable):
        def wrapper(self, *args, **kwargs):

            ev = event.Event()

            def answer_callback(data) -> None:
                ev.send(data)

            sio = socketio.Client()

            sio.connect(self.network_url, wait_timeout=1000)

            res = f(self, *args, **kwargs)
            # return schema: *data, key, role
            data, key = res[:-1], res[-1]

            # key = copy.copy(res[-2])
            enc_key = rsa.encrypt(key, self.pub_key)
            # url = res[-2]

            sio.emit(
                sio_ev,
                (self.base_url, *[*data, enc_key]), # , self.role]),
                callback=answer_callback
            )

            # TODO: make timeout dependent on length of data
            # TODO: two timeouts working for now because two stage comm.?
            # response = ev.wait()
            timeout = Timeout(10)
            try:
                response = ev.wait()
            except Timeout:
                pass
            # finally:
            #     timeout.cancel()
            try:
                response = ev.wait()
            except Timeout:
                print("answer timed out")
                response = ""
            finally:
                timeout.cancel()
            sio.disconnect()

            # response = response

            if response_fn is not None and isinstance(response, bytes):
                response = response_fn(self, key, response)

            return response
        return wrapper
    return _socket_wrapper

def login_response(
        conn: Any, # TODO: GridWSConnection not referencable at this point
        key: bytes,
        # url: str,
        response: bytes # Dict[str, str]
) -> Tuple[Dict, str]:
    # priv_key_path = glob.glob(f"./ssh-keys/private_ds_*_{url.split('/')[-1]}.pem")[0]
    # priv_key = read_priv_key(priv_key_path)
    # key = rsa.decrypt(key, priv_key)
    fernet = Fernet(key)
    response = fernet.decrypt(response)
    response = json.loads(response.decode())
    conn.session_token = response["token"]

    metadata = response["metadata"].encode("ISO-8859-1")
    metadata_pb = Metadata_PB()
    metadata_pb.ParseFromString(metadata)

    return metadata_pb, response["key"]

class GridWSConnection(WSConnection):

    def __init__(
            self,
            url: str,
            network_url: str = "http://localhost:7000",
            # role: str = "ds"
    ):
        self.base_url = url
        self.network_url = network_url

        self.session_token = None
        self.pub_key = None
        # if url.startswith("http"):
        #     url = url.split('/')[-1]
        # pub_key_path = glob.glob(f"ssh-keys/public_{url}.pem")[0]
        # self.pub_key = read_pub_key(pub_key_path)
        # self.role = role
        # self.priv_key = b""

    @socket_wrapper("pysyft")
    def _send_msg(self, msg: SyftMessage) -> Tuple[Union[bytes, str]]:
        msg_bytes: bytes = _serialize(obj=msg, to_bytes=True)  # type: ignore
        (enc_msg_bytes,), key = self.encode(msg_bytes.decode("ISO-8859-1"))
        return enc_msg_bytes, self.email, key
        # return msg_bytes, key

    @socket_wrapper("login", login_response)
    def login(self, credentials: Dict[str, str]) -> Tuple[Union[bytes, str]]:
        self.email = credentials["email"]
        if self.pub_key is None:
            _email = re.sub("[.@]", "", credentials["email"])
            # pub_key_path = glob.glob(f"ssh-keys/public_{self.url}_{_email}.pem")[0]
            _ip = self.base_url.split('/')[-1].split(':')[0]
            _ip = re.sub('[.:]', '', _ip)
            self.pub_key = read_pub_key(f"ssh-keys/public_{_ip}_{_email}.pem")
        (enc_pw,), key = self.encode(credentials["password"])
        # enc_key = rsa.encrypt(key, self.pub_key)
        return credentials["email"], enc_pw, key
        # return credentials["email"], credentials["password"]

    # Receive metadata only needed in setup and that is done via http
    # @socket_wrapper("metadata")
    # def _get_metadata(self) -> None:
    #     print("RECEIVING METADATA")
    #     return

    @staticmethod
    def encode(*args) -> Any:
        key = Fernet.generate_key()
        f = Fernet(key)
        return [f.encrypt(a.encode()) for a in args], key
