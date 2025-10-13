import argparse
import enum
import logging
import multiprocessing
import signal
import socket
import struct
import sys
from functools import partial
from selectors import (
    EVENT_READ,
    EVENT_WRITE,
    BaseSelector,
    DefaultSelector,
)
from typing import Any
from urllib.parse import urlparse

__all__ = ("proxy",)
__version__ = "0.1.1"

logger = logging.getLogger(__name__)

VERSION = 0x05  # SOCKS5
N_PACKET_HEADERS = 2


class Methods(enum.Enum):
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NOT_ACCEPTABLE = 0xFF


def create_server(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((host, port))
    sock.listen()
    return sock


class BaseSession:
    def __init__(
        self, conn: socket.socket, addr: tuple[str, int], selector: BaseSelector
    ):
        self.conn = conn
        self.addr = f"{addr[0]}:{addr[1]}"
        self.selector = selector
        self.closed = False

    def handle_events(self, events: int) -> None:
        if events & EVENT_READ:
            self.read()

        if events & EVENT_WRITE:
            self.write()

    def read(self) -> None:
        raise NotImplementedError

    def write(self) -> None:
        raise NotImplementedError

    def close(self, shutdown: bool = False) -> None:
        if not self.closed:
            self.selector.unregister(self.conn)

            if shutdown:
                self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.closed = True

    def __repr__(self):
        return f"<{self.__class__.__name__} addr={self.addr} closed={self.closed}>"


class ServerSession(BaseSession):
    def __init__(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        selector: BaseSelector,
        proxy: str,
    ):
        super().__init__(conn, addr, selector)
        self.proxy = proxy

    def read(self) -> None:
        conn, addr = self.conn.accept()
        logger.info(f"{addr[0]}:{addr[1]} connected")
        conn.setblocking(False)
        self.selector.register(
            conn,
            EVENT_READ | EVENT_WRITE,
            ClientSession(conn, addr, self.selector, self.proxy),
        )


class ClientSession(BaseSession):
    def __init__(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        selector: BaseSelector,
        proxy: str,
    ):
        super().__init__(conn, addr, selector)
        self.in_buff = b""
        self.out_buff = b""
        self.stage = self.stage_method_selection
        self.upstream: ProxySession | None = None
        self.proxy = urlparse(proxy)

    def read(self) -> None:
        data = self.conn.recv(1024)

        if not data:
            logger.info(f"{self.addr} disconnected")
            self.close()
            if self.upstream:
                self.upstream.close(shutdown=True)
            return

        logger.debug(f"{self.addr} > {data!r}")
        self.in_buff += data
        self.stage()

    def write(self) -> None:
        if self.out_buff:
            written = self.conn.send(self.out_buff)
            data = self.out_buff[:written]
            logger.debug(f"{self.addr} < {data!r}")
            self.out_buff = self.out_buff[written:]

    def connect_proxy(self) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        hostname = self.proxy.hostname or ""
        port = self.proxy.port or 80
        client.connect((hostname, port))
        client.setblocking(False)
        logger.info(f"{hostname}:{port} connected")

        proxy_session = ProxySession(
            client,
            (hostname, port),
            self.selector,
            self.proxy.username or "",
            self.proxy.password or "",
            self,
        )
        self.selector.register(client, EVENT_READ | EVENT_WRITE, proxy_session)

    def stage_method_selection(self) -> None:
        size = len(self.in_buff)
        if size < N_PACKET_HEADERS:
            return

        ver, nmethods = self.in_buff[:2]
        total_size = 2 + nmethods
        if ver != VERSION or nmethods < 1:
            self.close(shutdown=True)
        elif size >= total_size:
            method_options = struct.unpack(f">{nmethods}B", self.in_buff[2:total_size])
            self.in_buff = self.in_buff[total_size:]
            if Methods.NO_AUTH.value not in set(method_options):
                self.out_buff += struct.pack(
                    ">BB", VERSION, Methods.NOT_ACCEPTABLE.value
                )
                self.close(shutdown=True)
            else:
                self.out_buff += struct.pack(">BB", VERSION, Methods.NO_AUTH.value)
                if self.proxy:
                    self.connect_proxy()
                    self.stage = self.stage_tunnel

    def stage_tunnel(self) -> None:
        if self.in_buff and self.upstream is not None:
            self.upstream.out_buff += self.in_buff[:]
            self.in_buff = b""


class ProxySession(BaseSession):
    def __init__(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
        selector: BaseSelector,
        username: str,
        password: str,
        downstream: ClientSession,
    ):
        super().__init__(conn, addr, selector)
        self.username = username
        self.password = password
        self.in_buff = b""
        self.out_buff = struct.pack(
            ">BBB", VERSION, 0x01, Methods.USERNAME_PASSWORD.value
        )
        self.stage = self.stage_auth
        self.downstream = downstream

    def read(self) -> None:
        data = self.conn.recv(1024)

        if not data:
            logger.info(f"upstream {self.addr} disconnected")
            self.close()
            self.downstream.close(shutdown=True)
            return

        logger.debug(f"upstream {self.addr} > {data!r}")
        self.in_buff += data
        self.stage()

    def write(self) -> None:
        if self.out_buff:
            written = self.conn.send(self.out_buff)
            data = self.out_buff[:written]
            logger.debug(f"upstream {self.addr} < {data!r}")
            self.out_buff = self.out_buff[written:]

    def stage_auth(self) -> None:
        size = len(self.in_buff)
        if size < N_PACKET_HEADERS:
            return

        ver, method = self.in_buff[:2]
        self.in_buff = self.in_buff[2:]

        if ver != VERSION or method != Methods.USERNAME_PASSWORD.value:
            self.close()
            self.downstream.close(shutdown=True)
            return

        user_size = len(self.username)
        pass_size = len(self.password)
        self.out_buff += struct.pack(
            f">BB{user_size}sB{pass_size}s",
            0x01,
            user_size,
            self.username.encode("ascii"),
            pass_size,
            self.password.encode("ascii"),
        )
        self.stage = self.stage_verify

    def stage_verify(self) -> None:
        size = len(self.in_buff)
        if size < N_PACKET_HEADERS:
            return

        ver, status = self.in_buff[:2]
        self.in_buff = self.in_buff[2:]

        if status != 0x00:
            logger.warning(
                f"upstream {self.addr} failed to verify username/password ({status=})"
            )
            self.close()
            self.downstream.close(shutdown=True)
            return

        self.stage = self.stage_tunnel
        logger.info(f"Tunnel from {self.downstream.addr} to {self.addr} established")
        # important - this signals that the downstream can start tunneling to the upstream
        self.downstream.upstream = self
        self.downstream.stage()

    def stage_tunnel(self) -> None:
        if self.in_buff:
            self.downstream.out_buff += self.in_buff[:]
            self.in_buff = b""


def run(host: str, port: int, proxy: str) -> None:
    selector = DefaultSelector()
    sock = create_server(host, port)
    logger.info(f"Listening on {host}:{port}")
    server_session = ServerSession(sock, (host, port), selector, proxy)
    selector.register(
        sock,
        EVENT_READ,
        server_session,
    )

    sig_handler = partial(close, selector, server_session)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    while True:
        for key, events in selector.select(timeout=0.5):
            session = key.data
            session.handle_events(events)


def close(
    selector: BaseSelector, server_session: ServerSession, signum: int, frame: Any
) -> None:
    logger.info("Shutting down")
    server_session.close()

    to_close = []
    if len(selector.get_map()):
        for obj, key in selector.get_map().items():
            logger.warning(f"Leaking {obj} {key.data}")
            to_close.append(key.data)

    for session in to_close:
        session.close()

    selector.close()
    sys.exit()


class proxy:
    def __init__(self, proxy: str, host: str = "localhost", port: int = 1080):
        self.proxy = proxy
        self.host = host
        self.port = port
        self.proc: multiprocessing.Process | None = None
        self.uri = f"socks5://{host}:{port}"

    def start(self) -> None:
        self.proc = multiprocessing.Process(
            target=run, args=(self.host, self.port, self.proxy), name="slippers-server"
        )
        self.proc.start()

    def stop(self) -> None:
        if self.proc is not None and self.proc.is_alive():
            self.proc.terminate()
            self.proc.join()

    def __enter__(self) -> str:
        self.start()
        return self.uri

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host",
        action="store",
        type=str,
        required=False,
        default="localhost",
    )
    parser.add_argument(
        "--port",
        action="store",
        type=int,
        required=False,
        default=1080,
    )
    parser.add_argument(
        "--log-level",
        action="store",
        type=str,
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
    )
    parser.add_argument(
        "upstream",
        action="store",
        type=str,
        help='The upstream SOCKS5 server. Should be formatted like "socks5://username:password@host:port".',
    )
    return parser.parse_args()


def main(args) -> None:
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    run(args.host, args.port, args.upstream)


if __name__ == "__main__":
    main(parse_args())
