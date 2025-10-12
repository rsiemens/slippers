import struct
import enum
import logging
from selectors import (
    DefaultSelector,
    EVENT_READ,
    EVENT_WRITE,
    BaseSelector,
)
import socket
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

VERSION = 0x05  # SOCKS5


class Methods(enum.Enum):
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NOT_ACCEPTABLE = 0xFF


def create_server(host: str = "127.0.0.1", port: int = 1080) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((host, port))
    sock.listen()
    return sock


class BaseSession:
    def __init__(self, conn: socket.socket, selector: BaseSelector):
        self.conn = conn
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


class ServerSession(BaseSession):
    def __init__(
        self,
        conn: socket.socket,
        selector: BaseSelector,
        proxy: str,
    ):
        super().__init__(conn, selector)
        self.proxy = proxy

    def read(self) -> None:
        conn, addr = self.conn.accept()
        logger.info(f"{addr[0]} connected")
        conn.setblocking(False)
        self.selector.register(
            conn,
            EVENT_READ | EVENT_WRITE,
            ClientSession(conn, self.selector, addr, self.proxy),
        )


class ClientSession(BaseSession):
    def __init__(
        self,
        conn: socket.socket,
        selector: BaseSelector,
        addr: tuple[str, int],
        proxy: str,
    ):
        super().__init__(conn, selector)
        self.host, self.port = addr
        self.in_buff = b""
        self.out_buff = b""
        self.stage = self.stage_method_selection
        self.upstream: ProxySession | None = None
        self.proxy = urlparse(proxy)

    def read(self) -> None:
        data = self.conn.recv(1024)

        if not data:
            logger.info(f"{self.host} disconnected")
            self.close()
            if self.upstream:
                self.upstream.close(shutdown=True)
            return

        logger.debug(f"{self.host}:> {data!r}")
        self.in_buff += data
        self.stage()

    def write(self) -> None:
        if self.out_buff:
            written = self.conn.send(self.out_buff)
            data = self.out_buff[:written]
            logger.debug(f"{self.host}:< {data!r}")
            self.out_buff = self.out_buff[written:]

    def connect_proxy(self) -> None:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        hostname = self.proxy.hostname or ""
        port = self.proxy.port or 80
        client.connect((hostname, port))
        proxy_session = ProxySession(
            client,
            self.selector,
            (hostname, port),
            self.proxy.username or "",
            self.proxy.password or "",
            self,
        )
        self.selector.register(client, EVENT_READ | EVENT_WRITE, proxy_session)

    def stage_method_selection(self) -> None:
        size = len(self.in_buff)
        if size < 2:
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
        selector: BaseSelector,
        addr: tuple[str, int],
        username: str,
        password: str,
        downstream: ClientSession,
    ):
        super().__init__(conn, selector)
        self.host, self.port = addr
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
            logger.info(f"upstream {self.host} disconnected")
            self.close()
            self.downstream.close(shutdown=True)
            return

        logger.debug(f"upstream {self.host}:> {data!r}")
        self.in_buff += data
        self.stage()

    def write(self) -> None:
        if self.out_buff:
            written = self.conn.send(self.out_buff)
            data = self.out_buff[:written]
            logger.debug(f"upstream {self.host}:< {data!r}")
            self.out_buff = self.out_buff[written:]

    def stage_auth(self) -> None:
        size = len(self.in_buff)
        if size < 2:
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
        if size < 2:
            return

        ver, status = self.in_buff[:2]
        self.in_buff = self.in_buff[2:]

        if status != 0x00:
            logger.debug(
                f"upstream {self.host} failed to verify username/password ({status=})"
            )
            self.close()
            self.downstream.close(shutdown=True)
            return

        self.stage = self.stage_tunnel
        # important - this signals that the downstream can start tunneling to the upstream
        self.downstream.upstream = self
        self.downstream.stage()

    def stage_tunnel(self) -> None:
        if self.in_buff:
            self.downstream.out_buff += self.in_buff[:]
            self.in_buff = b""


if __name__ == "__main__":
    import os
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    HOST = "127.0.0.1"
    PORT = 1080
    selector = DefaultSelector()
    sock = create_server(HOST, PORT)
    logger.info(f"Listening on {HOST}:{PORT}")
    server_session = ServerSession(
        sock,
        selector,
        f"socks5://{os.getenv('VPN_USERNAME')}:{os.getenv('VPN_PASSWORD')}@new-york.us.socks.nordhold.net:1080",
    )
    selector.register(
        sock,
        EVENT_READ,
        server_session,
    )

    while True:
        try:
            for key, events in selector.select(timeout=0.5):
                session = key.data
                session.handle_events(events)
        except KeyboardInterrupt:
            break

    server_session.close()
    leaks = len(selector.get_map())
    if leaks:
        for obj, key in selector.get_map().items():
            logger.debug(f"Leaking {obj} {key}")

    selector.close()
