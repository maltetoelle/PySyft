import sys
# third party
from eventlet import event
from eventlet.timeout import Timeout
from flask import Flask, session, request
from flask_socketio import SocketIO, emit
import functools
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
import pandas as pd
from typing import Any, Dict, Tuple

from syft.grid.messages.association_messages import ReceiveAssociationRequestMessage
from syft.grid.messages.association_messages import RespondAssociationRequestMessage
from syft.grid.messages.association_messages import RespondAssociationRequestResponse
from syft.core.common.serde.serialize import _serialize

# grid relative
from ..routes import association_requests_blueprint
from ..routes import dcfl_blueprint
from ..routes import groups_blueprint
from ..routes import roles_blueprint
from ..routes import root_blueprint
from ..routes import search_blueprint
from ..routes import setup_blueprint
from ..routes import users_blueprint
from ..utils.executor import executor
from ..utils.monkey_patch import mask_payload_fast
from .nodes.domain import GridDomain
from .nodes.network import GridNetwork
from .nodes.worker import GridWorker
from .services.association_request import recv_association_request_msg

sys.path.append("../")
from src.main.routes.auth import token_required
from src.main.core.exceptions import (
    MissingRequestKeyError, AuthorizationError
)

node = None


def get_node():
    global node
    return node


def create_worker_app(app, args):
    # Register HTTP blueprints
    # Here you should add all the blueprints related to HTTP routes.
    app.register_blueprint(root_blueprint, url_prefix=r"/")

    # Register WebSocket blueprints
    # Here you should add all the blueprints related to WebSocket routes.
    # sockets.register_blueprint()

    global node
    node = GridWorker(name=args.name, domain_url=args.domain_address)

    app.config["EXECUTOR_PROPAGATE_EXCEPTIONS"] = True
    app.config["EXECUTOR_TYPE"] = "thread"
    executor.init_app(app)

    return app


def create_network_app(app, args, testing=False) -> Tuple[Flask, SocketIO]:
    test_config = None
    if args.start_local_db:
        test_config = {"SQLALCHEMY_DATABASE_URI": "sqlite:///nodedatabase.db"}

    app.register_blueprint(roles_blueprint, url_prefix=r"/roles")
    app.register_blueprint(users_blueprint, url_prefix=r"/users")
    app.register_blueprint(setup_blueprint, url_prefix=r"/setup")
    app.register_blueprint(root_blueprint, url_prefix=r"/")
    app.register_blueprint(search_blueprint, url_prefix=r"/search")
    app.register_blueprint(
        association_requests_blueprint, url_prefix=r"/association-requests/"
    )

    # Register WebSocket blueprints
    # Here you should add all the blueprints related to WebSocket routes.
    # sockets.register_blueprint()

    # grid relative
    from .database import Role
    from .database import User
    from .database import db
    from .database import seed_network_db
    from .database import set_database_config

    global node
    node = GridNetwork(name=args.name)

    socketio = None
    if(args.use_websockets):
        socketio = SocketIO(app, manage_session=False)

        df = pd.DataFrame(columns=["url", "sid"])
        df.set_index("url", inplace=True)

        def _answer_callback(ev, data) -> None:
            ev.send(data)
        answer_callback = lambda ev: functools.partial(_answer_callback, ev)

        @socketio.on("register_client")
        def register_client(url: str):
            if not url in df.index:
                df.loc[url] = pd.Series(dtype=str)
            df.loc[url]["sid"] = request.sid
            print(df)

        @socketio.on("login")
        def login(url: str, email: str, password: str, key: bytes):
            ev = event.Event()
            sid = df.loc[url]["sid"]
            emit(
                "login", (email, password, key, url), to=sid,
                callback=answer_callback(ev)
            )
            timeout = Timeout(10)
            try:
                response = ev.wait()
            except Timeout:
                print("answer timed out")
                response = ""
            finally:
                timeout.cancel()

            # TODO: SESSION TOKEN
            return response # , url

        # @socketio.on("metadata")
        # def metadata(url: str):
        #     ev = event.Event()
        #     sid = df.loc[url]["sid"]
        #     emit(
        #         "metadata", to=sid,
        #         callback=answer_callback(ev)
        #     )

        @socketio.on("pysyft")
        def pysyft(url: str, data: bytes, key: bytes, email: str):
            ev = event.Event()
            sid = df.loc[url]["sid"]
            # TODO: check if message with reply
            emit(
                "pysyft", (data, key, email), to=sid,
                callback=answer_callback(ev)
            )
            timeout = Timeout(120)
            try:
                response = ev.wait()
            except Timeout:
                print("answer timed out")
                response = ""
            finally:
                timeout.cancel()
            return response #, url

        @socketio.on("receive_association_request")
        def receive_association_request(payload: Dict[str, str]):
            msg = ReceiveAssociationRequestMessage(
                address=node.address,
                content=payload,
                reply_to=node.address
            )
            response_msg = recv_association_request_msg(msg=msg, node=node, verify_key=node.verify_key)

            return _serialize(obj=response_msg, to_bytes=True).decode("ISO-8859-1")

        @app.route("/ws_conn/respond_association_request", methods=["POST"])
        @token_required
        def accept_association_request(user: Any):
            # keys: handshake_value of req, value ["accept", "deny"]
            content = request.json

            msg = RespondAssociationRequestMessage(
                address=node.address,
                content=content,
                reply_to=node.address
            )

            # Get Payload Content
            address = msg.content.get("address", None)
            current_user_id = msg.content.get("current_user", None)
            handshake_value = msg.content.get("handshake_value", None)
            value = msg.content.get("value", None)
            sender_address = msg.content.get("sender_address", None)

            users = node.users

            if not current_user_id:
                current_user_id = users.first(
                    verify_key=node.verify_key.encode(encoder=HexEncoder).decode("utf-8")
                ).id

            # Check if handshake/address/value fields are empty
            missing_paramaters = not address or not handshake_value or not value
            if missing_paramaters:
                raise MissingRequestKeyError(
                    message="Invalid request payload, empty fields (adress/handshake/value)!"
                )

            allowed = node.users.can_manage_infrastructure(user_id=current_user_id)

            if allowed:
                # Set the status of the Association Request according to the "value" field recived
                association_requests = node.association_requests
                association_requests.set(handshake_value, value)

                # Create POST request to the address received in the body
                payload = {
                    "address": sender_address,
                    "handshake": handshake_value,
                    "value": value,
                    "sender_address": address,
                }
                # url = address + "/association-requests/receive"
                print("/ws_conn/respond_association_request df", df)

                # response = post(url=url, json=payload)
                sid = df.loc[address]["sid"]

                ev = event.Event()
                # TODO: check if message with reply
                socketio.emit(
                    "receive_association_request", payload, to=sid,
                    callback=answer_callback(ev)
                )
                timeout = Timeout(10)
                try:
                    response = ev.wait()
                except Timeout:
                    print("answer timed out")
                    response = ""
                finally:
                    timeout.cancel()

                # TODO: status code from socketio client
                # response_message = (
                #     "Association request replied!"
                #     if response.status_code == 200
                #     else "Association request could not be replied! Please, try again."
                # )
            else:
                raise AuthorizationError("You're not allowed to create an Association Request!")

            # TODO: error handling
            response_msg =  RespondAssociationRequestResponse(
                address=msg.reply_to,
                status_code=200, # response.status_code,
                content={"msg": "Association request replied!"}#response_message},
            )
            return {"message": _serialize(obj=response_msg, to_bytes=True).decode("ISO-8859-1")}

        # TODO: token required from domain!
        @app.route("/search-datasets", methods=["GET"])
        @token_required
        def search(user: Any):
            # TODO: send serialized messages instead of creating them here
            # msg = NetworkSearchMessage(
            #     address=node.address,
            #     content={},
            #     reply_to=node.address
            # )
            #
            # queries = set(msg.content.get("query", []))

            content = request.json

            print("search-datasets", content)

            queries = set(content["queries"])
            associations = node.association_requests.associations()
            print("search-datasets associations", associations)

            def filter_domains(url):
                print("search-datasets filter_domains", df)
                # datasets = json.loads(requests.get(url + "/data-centric/tensors").text)
                sid = df.loc[url]["sid"]
                ev = event.Event()
                # TODO: check if message with reply
                socketio.emit(
                    "get-all-tensors", to=sid,
                    callback=answer_callback(ev)
                )
                timeout = Timeout(10)
                try:
                    datasets = ev.wait()
                except Timeout:
                    print("answer timed out")
                    datasets = {}
                finally:
                    timeout.cancel()

                print("search-datasets filter_domains", datasets)

                for dataset in datasets["tensors"]:
                    if queries.issubset(set(dataset["tags"])):
                        return True
                return False

            filtered_nodes = list(filter(lambda x: filter_domains(x.address), associations))
            print("search-datasets", filtered_nodes)

            match_nodes = [node.address for node in filtered_nodes]

            return {"match_nodes": match_nodes}
            # return NetworkSearchResponse(
            #     address=msg.reply_to, status_code=200, content={"match-nodes": match_nodes}
            # )

        @app.route("/ws_conn/create_user", methods=["POST"])
        @token_required
        def create_user(user: Any):
            # TODO: make sure user does not exists already
            data = request.json
            if any([x.email== data["email"] for x in node.users.all()]):
                return {"message", "User already exists!"}, 403
            _private_key = SigningKey.generate()
            _user = node.users.signup(
                email=data["email"], # _email,
                password=data["password"], # _password,
                role=node.roles.first(name="Administrator").id, # TODO: add user role to network
                private_key=_private_key.encode(encoder=HexEncoder).decode("utf-8"),
                verify_key=_private_key.verify_key.encode(encoder=HexEncoder).decode(
                    "utf-8"
                ),
            )
            return {"message": "User created successfully!"}

    # Set SQLAlchemy configs
    set_database_config(app, test_config=test_config)
    s = app.app_context().push()

    db.create_all()

    if not testing:
        if len(db.session.query(Role).all()) == 0:
            seed_network_db()

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

    return app, socketio


def create_domain_app(app, args, testing=False):
    test_config = None
    if args.start_local_db:
        test_config = {"SQLALCHEMY_DATABASE_URI": "sqlite:///nodedatabase.db"}

    # Register HTTP blueprints
    # Here you should add all the blueprints related to HTTP routes.
    app.register_blueprint(roles_blueprint, url_prefix=r"/roles")
    app.register_blueprint(users_blueprint, url_prefix=r"/users")
    app.register_blueprint(setup_blueprint, url_prefix=r"/setup")
    app.register_blueprint(groups_blueprint, url_prefix=r"/groups")
    app.register_blueprint(dcfl_blueprint, url_prefix=r"/dcfl")
    app.register_blueprint(root_blueprint, url_prefix=r"/")
    app.register_blueprint(
        association_requests_blueprint, url_prefix=r"/association-requests"
    )

    # Register WebSocket blueprints
    # Here you should add all the blueprints related to WebSocket routes.
    # sockets.register_blueprint()

    # grid relative
    from .database import Role
    from .database import User
    from .database import db
    from .database import seed_db
    from .database import set_database_config

    global node
    node = GridDomain(name=args.name)

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
