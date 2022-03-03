"""
Note:

This file should be used only for development purposes.
Use the Flask built-in web server isn't suitable for production.
For production, we need to put it behind real web server able to communicate
with Flask through a WSGI protocol.
A common choice for that is Gunicorn.
"""

# stdlib
import argparse
import os
from threading import Thread

# third party
from app import create_app
from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler

parser = argparse.ArgumentParser(description="Run PyGrid application.")


parser.add_argument(
    "--port",
    "-p",
    type=int,
    help="Port number of the socket server, e.g. --port=5000. Default is os.environ.get('GRID_NODE_PORT', 5000).",
    default=os.environ.get("GRID_NODE_PORT", 5000),
)

parser.add_argument(
    "--host",
    type=str,
    help="Grid node host, e.g. --host=0.0.0.0. Default is os.environ.get('GRID_NODE_HOST','0.0.0.0').",
    default=os.environ.get("GRID_NODE_HOST", "0.0.0.0"),
)

parser.add_argument(
    "--name",
    type=str,
    help="Grid node name, e.g. --name=OpenMined. Default is os.environ.get('GRID_NODE_NAME','OpenMined').",
    default=os.environ.get("GRID_NODE_NAME", "OpenMined"),
)

parser.add_argument(
    "--start_local_db",
    dest="start_local_db",
    action="store_true",
    help="If this flag is used a SQLAlchemy DB URI is generated to use a local db.",
)

parser.add_argument(
    "--use-websockets",
    dest="use_websockets",
    action="store_true",
    help="If this flag is used websockets will be used instead of HTTP.",
)

parser.add_argument(
    "--network_url",
    type=str,
    help="Network grid node host, e.g. --host=0.0.0.0. Default is localhost.",
    default=os.environ.get("NETWORK_HOST", "http://localhost:5001"),
)

parser.set_defaults(use_test_config=False)

if __name__ == "__main__":
    args = parser.parse_args()

    app, socketio_client = create_app(args)
    _address = "http://{}:{}".format(args.host, args.port)

    if(args.use_websockets):


        if args.network_url is None:
            network_url = os.environ.get("NETWORK_URL", "129.206.7.138")
            port = os.environ.get("PORT", 5000)

            t = Thread(target=lambda: app.run(host="0.0.0.0", port=port)).start()
            socketio_client.connect(f"http://{network_url}", wait_timeout=10)
        else:
            t = Thread(target=lambda: app.run(host="0.0.0.0", port=args.port)).start()
            # socketio_client.connect("http://129.206.7.138", wait_timeout=10)
            socketio_client.connect(f"http://{args.network_url}", wait_timeout=10)

    else:
        server = pywsgi.WSGIServer(
            (args.host, args.port), app, handler_class=WebSocketHandler
        )
        server.serve_forever()
