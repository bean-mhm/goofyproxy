"""
this script runs a goofy client and server pair connected via a local/loopback
socket (127.0.0.1) using `SocketIo`. other programs or devices on the LAN can
connect to the goofy client's SOCKS5 proxy. this is useful for debugging
`GoofyClient` and `GoofyServer` without a complex `GoofyIo`.
"""

import socket
import threading
import queue

from goofyproxy.address_filter import *
from goofyproxy.goofyio import SocketIo
from goofyproxy.goofy_client import GoofyClient
from goofyproxy.goofy_server import GoofyServer
from goofyproxy.common import *


def server_thread(port_queue):
    log = make_logger("server", logging.DEBUG)

    # create a listening TCP socket on a random port,
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('127.0.0.1', 0))          # bind to random port
    _, port = server_sock.getsockname()
    server_sock.listen(1)
    log.info(f"listening at {format_addr(server_sock.getsockname())}")

    # signal the port to the main thread
    port_queue.put(port)

    # wait for client connection from the main thread connects
    sock, addr = server_sock.accept()
    server_sock.close()
    log.info(
        f"accepted client {format_addr(sock.getpeername())}. starting goofy "
        f"server."
    )

    # start goofy server
    GoofyServer(
        io=SocketIo(sock),
        log_level=logging.DEBUG
    )


def main():
    log = make_logger("main", logging.DEBUG)

    port_queue = queue.Queue()

    # start the server thread
    log.info("starting the server thread")
    t = threading.Thread(
        name="server thread",
        target=server_thread,
        args=(port_queue,),
        daemon=True
    )
    t.start()

    # wait for the server to signal the port
    port = port_queue.get()
    log.info(f"server thread signaled port {port}")

    # connect to the server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", port))
    log.info(
        f"connected to the server socket at {format_addr(sock.getpeername())}. "
        f"starting goofy client."
    )

    # start goofy client
    GoofyClient(
        io=SocketIo(sock),
        host="0.0.0.0",
        port=1080,
        log_level=logging.DEBUG
    )


if __name__ == "__main__":
    main()
