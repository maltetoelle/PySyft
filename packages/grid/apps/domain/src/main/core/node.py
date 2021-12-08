# std lib
from typing import Dict, Any, Union
import json
import glob
import re
from functools import wraps
import requests
import os

# third party
from flask_sockets import Sockets
from main import ws
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
import socketio
from cryptography.fernet import Fernet
import rsa
import jwt
from nacl.encoding import HexEncoder
from flask import request
from eventlet import event
import torch as th

#syft
from syft import deserialize
from syft.grid.client.grid_ws_connection import read_priv_key
from syft.core.common.serde.serialize import _serialize
from syft.grid.messages.association_messages import (
    SendAssociationRequestMessage, ReceiveAssociationRequestMessage
)
from syft.core.common.message import SignedImmediateSyftMessageWithReply
from syft.core.common.message import SignedImmediateSyftMessageWithoutReply
from syft.core.remote_dataloader.remote_dataloader import RemoteDataset
from syft.grid.connections import get_response

# grid relative
from ..routes import association_requests_blueprint
from ..routes import dcfl_blueprint
from ..routes import groups_blueprint
from ..routes import mcfl_blueprint
from ..routes import roles_blueprint
from ..routes import root_blueprint
from ..routes import search_blueprint
from ..routes import setup_blueprint
from ..routes import users_blueprint
from ..utils.executor import executor
from .nodes.domain import GridDomain
from .nodes.network import GridNetwork
from .nodes.worker import GridWorker
from .sleepy_until_configured import SleepyUntilConfigured
from ..core.exceptions import UserNotFoundError
from ..core.services.association_request import recv_association_request_msg
from ..routes.auth import token_required
from ..core.exceptions import MissingRequestKeyError

node = None


def get_node():
    global node
    return node


def get_own_ip() -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def create_worker_app(app, args):
    # Register HTTP blueprints
    # Here you should add all the blueprints related to HTTP routes.
    app.register_blueprint(root_blueprint, url_prefix=r"/")

    # Register WebSocket blueprints
    # Here you should add all the blueprints related to WebSocket routes.

    global node
    node = GridWorker(name=args.name, domain_url=args.domain_address)

    app.config["EXECUTOR_PROPAGATE_EXCEPTIONS"] = True
    app.config["EXECUTOR_TYPE"] = "thread"
    executor.init_app(app)

    return app


def create_network_app(app, args, testing=False):
    test_config = None
    if args.start_local_db:
        test_config = {"SQLALCHEMY_DATABASE_URI": "sqlite:///nodedatabase.db"}

    app.register_blueprint(roles_blueprint, url_prefix=r"/roles")
    app.register_blueprint(users_blueprint, url_prefix=r"/users")
    app.register_blueprint(setup_blueprint, url_prefix=r"/setup")
    app.register_blueprint(root_blueprint, url_prefix=r"/")
    app.register_blueprint(search_blueprint, url_prefix=r"/search")
    app.register_blueprint(
        association_requests_blueprint, url_prefix=r"/association-requests"
    )

    # Register WebSocket blueprints
    # Here you should add all the blueprints related to WebSocket routes.

    # grid relative
    from .database import Role
    from .database import User
    from .database import db
    from .database import seed_db
    from .database import set_database_config

    global node
    node = GridNetwork(name=args.name)

    # Set SQLAlchemy configs
    set_database_config(app, test_config=test_config)
    s = app.app_context().push()

    db.create_all()

    if not testing:
        if len(db.session.query(Role).all()) == 0:
            seed_db()

        role = db.session.query(Role.id).filter_by(name="Owner").first()
        user = User.query.filter_by(role=role.id).first()
        if user:
            signing_key = SigningKey(
                user.private_key.encode("utf-8"), encoder=HexEncoder
            )
            node.signing_key = signing_key
            node.verify_key = node.signing_key.verify_key
            node.root_verify_key = node.verify_key
    db.session.commit()

    app.config["EXECUTOR_PROPAGATE_EXCEPTIONS"] = True
    app.config["EXECUTOR_TYPE"] = "thread"
    executor.init_app(app)

    return app


def create_domain_app(app, args, testing=False):
    test_config = None

    if args.start_local_db:
        test_config = {"SQLALCHEMY_DATABASE_URI": "sqlite:///nodedatabase.db"}

    # Bind websocket in Flask app instance
    sockets = Sockets(app)

    # Register HTTP blueprints
    # Here you should add all the blueprints related to HTTP routes.
    app.register_blueprint(roles_blueprint, url_prefix=r"/roles")
    app.register_blueprint(users_blueprint, url_prefix=r"/users")
    app.register_blueprint(setup_blueprint, url_prefix=r"/setup")
    app.register_blueprint(groups_blueprint, url_prefix=r"/groups")
    app.register_blueprint(dcfl_blueprint, url_prefix=r"/data-centric")
    app.register_blueprint(mcfl_blueprint, url_prefix=r"/model-centric")
    app.register_blueprint(root_blueprint, url_prefix=r"/")
    app.register_blueprint(
        association_requests_blueprint, url_prefix=r"/association-requests"
    )

    # Register WebSocket blueprints
    # Here you should add all the blueprints related to WebSocket routes.
    sockets.register_blueprint(ws, url_prefix=r"/")

    # grid relative
    from .database import Role
    from .database import SetupConfig
    from .database import User
    from .database import db
    from .database import seed_db
    from .database import set_database_config

    global node
    node = GridDomain(name=args.name)

    socketio_client = None
    if(args.use_websockets):
        http_session = requests.Session()
        http_session.proxies = {
            "http": os.environ.get("http_proxy"),
            "https": os.environ.get("https_proxy")
        }
        socketio_client = socketio.Client(http_session=http_session) # , engineio_logger=True)
        def sio_token_required(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                import pdb;pdb.set_trace()
                token = None
                current_user = None
                if token:
                    data = jwt.decode(
                        token, app.config["SECRET_KEY"], algorithms="HS256"
                    )
                    current_user = User.query.get(data["id"])
                if current_user is None: # and not optional:
                    raise UserNotFoundError
                return f(current_user, *args, **kwargs)
            return wrapper

        def decode(key: bytes, *args) -> Any:
            f = Fernet(key)
            return [f.decrypt(a).decode() for a in args]

        def encode(key: bytes, *args) -> Any:
            f = Fernet(key)
            return [f.encrypt(a) for a in args]
        
        @socketio_client.on("connect")
        def connect() -> None:
            print("connected")
            url = f"http://{get_own_ip()}:{args.port}"
            socketio_client.emit("register_client", url)

        @socketio_client.on("login")
        def login(email: str, password: bytes, key: bytes, url: str) -> Dict[str, Any]:
            _ip = get_own_ip()
            _ip = re.sub('[.:]', '', _ip)
            priv_key_path = glob.glob(os.path.expanduser( '~' ) + f"/.ssh/private_{_ip}_{re.sub('[.@]', '', email)}.pem")[0]
            priv_key = read_priv_key(priv_key_path)
            key = rsa.decrypt(key, priv_key)
            password, = decode(key, password)
            with app.app_context():
                response = node.login(email=email, password=password)
            response = json.dumps(response)
            response, = encode(key, response.encode())
            return response

        @socketio_client.on("pysyft")
        def pysyft(data: bytes, email: str, key: bytes) -> Union[bytes, str]:
            _ip = get_own_ip()
            _ip = re.sub('[.:]', '', _ip)
            priv_key_path = glob.glob(os.path.expanduser( '~' ) + f"/.ssh/private_{_ip}_{re.sub('[.@]', '', email)}.pem")[0]
            priv_key = read_priv_key(priv_key_path)
            key = rsa.decrypt(key, priv_key)
            data, = decode(key, data)
            data = data.encode("ISO-8859-1")
            with app.app_context():
                obj_msg = deserialize(blob=data, from_bytes=True)
                if isinstance(obj_msg, SignedImmediateSyftMessageWithReply):
                    reply = node.recv_immediate_msg_with_reply(msg=obj_msg)
                    reply_msg_bytes = _serialize(obj=reply, to_bytes=True)
                    enc_reply_msg_bytes, = encode(key, reply_msg_bytes.decode("ISO-8859-1").encode())
                    return enc_reply_msg_bytes
                elif isinstance(obj_msg, SignedImmediateSyftMessageWithoutReply):
                    node.recv_immediate_msg_without_reply(msg=obj_msg)
                else:
                    node.recv_eventual_msg_without_reply(msg=obj_msg)
                return ""

        # TODO: key based encryption here as well!
        @socketio_client.on("get-all-tensors")
        def get_all_tensors():
            with app.app_context():
                if hasattr(node, "memory_store"):
                    tensors = node.memory_store.get_objects_of_type(obj_type=(th.Tensor, RemoteDataset))
                if not len(tensors):
                    # TODO: write tensors in memory store if not there after restart
                    tensors = node.store.get_objects_of_type(obj_type=(th.Tensor, RemoteDataset))

                result = []

                for tensor in tensors:
                    result.append(
                        {
                            "id": str(tensor.id.value),
                            "tags": tensor.tags,
                            "description": tensor.description,
                        }
                    )

                return {"tensors": result}

        @app.route("/ws_conn/send_association_request", methods=["POST"])
        @token_required
        def send_association_request(user: Any):
            content = request.json
            msg = SendAssociationRequestMessage(
                address=node.address,
                content=content,
                reply_to=node.address
            )

            name = msg.content.get("name", None)
            target_address = msg.content.get("address", None)
            current_user_id = msg.content.get("current_user", None)
            sender_address = msg.content.get("sender_address", None)

            users = node.users

            if not current_user_id:
                current_user_id = users.first(
                    verify_key=node.verify_key.encode(encoder=HexEncoder).decode("utf-8")
                ).id

            # Check if name/address fields are empty
            missing_paramaters = not name or not target_address
            if missing_paramaters:
                raise MissingRequestKeyError(
                    message="Invalid request payload, empty fields (name/adress)!"
                )

            allowed = node.users.can_manage_infrastructure(user_id=current_user_id)

            if allowed:
                association_requests = node.association_requests
                association_request_obj = association_requests.create_association_request(
                    name, target_address, sender_address
                )
                handshake_value = association_request_obj.handshake_value

                # Create POST request to the address recived in the body
                payload = {
                    "name": name,
                    "address": sender_address,
                    "handshake": handshake_value,
                    "sender_address": target_address,
                }

                ev = event.Event()

                socketio_client.emit(
                    "receive_association_request",
                    payload,
                    callback=lambda msg: ev.send(msg)
                )
                response = get_response(ev, default_return_value="")
                return {"message": response}

        @socketio_client.on("receive_association_request")
        def _receive_association_request(payload: Dict[str, str]):
            with app.app_context():
                msg = ReceiveAssociationRequestMessage(
                    address=node.address,
                    content=payload,
                    reply_to=node.address
                )
                response_msg = recv_association_request_msg(msg=msg, node=node, verify_key=node.verify_key)

                return response_msg.content


    # Set SQLAlchemy configs
    set_database_config(app, test_config=test_config)
    app.app_context().push()
    db.create_all()

    if not testing:
        if len(db.session.query(Role).all()) == 0:
            seed_db()

        if len(db.session.query(SetupConfig).all()) != 0:
            node.name = db.session.query(SetupConfig).first().domain_name

        role = db.session.query(Role.id).filter_by(name="Owner").first()
        user = User.query.filter_by(role=role.id).first()
        if user:
            signing_key = SigningKey(
                user.private_key.encode("utf-8"), encoder=HexEncoder
            )
            node.signing_key = signing_key
            node.verify_key = node.signing_key.verify_key
            node.root_verify_key = node.verify_key

        # Register global middlewares
        # Always after context is pushed
        app.wsgi_app = SleepyUntilConfigured(app, app.wsgi_app)
    db.session.commit()

    app.config["EXECUTOR_PROPAGATE_EXCEPTIONS"] = True
    app.config["EXECUTOR_TYPE"] = "thread"
    executor.init_app(app)

    return app, socketio_client
