import signal
import socket
import unittest
from selectors import EVENT_READ, EVENT_WRITE, BaseSelector, DefaultSelector
from typing import cast
from unittest.mock import ANY, MagicMock, patch

from slippers import BaseSession, ClientSession, ProxySession, ServerSession, close

METH_SELECT_REQ = b"\x05\x01\x00"
METH_SELECT_RES = b"\x05\x00"
METH_SELECT_RES_NOT_ACCEPTABLE = b"\x05\xff"
METH_SELECT_AUTH_REQ = b"\x05\x01\x02"
METH_SELECT_AUTH_RES = b"\x05\x02"


class BaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_selector = MagicMock(spec=DefaultSelector)
        self.mock_conn = MagicMock(spec=socket.socket)
        self.mock_conn.fileno.return_value = 9


class BaseSessionTestCase(BaseTestCase):
    class MySession(BaseSession):
        def __init__(
            self, conn: socket.socket, addr: tuple[str, int], selector: BaseSelector
        ):
            super().__init__(conn, addr, selector)
            self.r_count = 0
            self.w_count = 0

        def read(self) -> None:
            super().read()
            self.r_count += 1

        def write(self) -> None:
            super().write()
            self.w_count += 1

    def setUp(self) -> None:
        super().setUp()
        self.session = self.MySession(
            conn=self.mock_conn, addr=("127.0.0.1", 4321), selector=self.mock_selector
        )

    def test_handle_events(self) -> None:
        self.session.handle_events(EVENT_READ)
        self.session.handle_events(EVENT_WRITE)
        self.session.handle_events(EVENT_READ | EVENT_WRITE)
        self.assertEqual(self.session.r_count, 2)
        self.assertEqual(self.session.w_count, 2)

    def test_read(self) -> None:
        self.mock_conn.recv.return_value = METH_SELECT_REQ
        with patch.object(self.session, "stage") as mock_stage:
            self.session.read()

        self.assertEqual(self.session.in_buff, METH_SELECT_REQ)
        mock_stage.assert_called_once()
        self.assertFalse(self.session.closed)

    def test_read_no_data(self) -> None:
        self.mock_conn.recv.return_value = b""
        with (
            patch.object(self.session, "stage") as mock_stage,
            self.assertLogs("slippers", level="DEBUG") as log_ctx,
        ):
            self.session.read()

        self.assertEqual(log_ctx.records[0].msg, "127.0.0.1:4321 (9) disconnected")
        self.assertEqual(self.session.in_buff, b"")
        mock_stage.assert_not_called()
        self.assertTrue(self.session.closed)

    def test_write(self) -> None:
        self.session.write()
        self.mock_conn.send.assert_not_called()

        self.session.out_buff = METH_SELECT_RES
        self.mock_conn.send.return_value = len(METH_SELECT_RES)
        self.session.write()
        written = self.mock_conn.send.call_args.args[0]
        self.assertEqual(written, METH_SELECT_RES)
        self.assertEqual(self.session.out_buff, b"")

    def test_close(self) -> None:
        self.session.close()

        self.assertTrue(self.session.closed)
        self.mock_selector.unregister.assert_called_once_with(self.mock_conn)
        self.mock_conn.shutdown.assert_called_once()
        self.mock_conn.close.assert_called_once()

        self.session.close()
        # Closing a session a second time is idempotent
        self.assertTrue(self.session.closed)
        self.assertEqual(self.mock_selector.unregister.call_count, 1)
        self.assertEqual(self.mock_conn.shutdown.call_count, 1)
        self.assertEqual(self.mock_conn.close.call_count, 1)

    def test_repr(self) -> None:
        self.assertEqual(
            repr(self.session), "<MySession addr=127.0.0.1:4321 closed=False>"
        )


class ServerSessionTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.session = ServerSession(
            conn=self.mock_conn,
            addr=("127.0.0.1", 1080),
            selector=self.mock_selector,
            proxy="socks5://foo:bar@my-socks-server.net:1080",
        )

    def test_read(self) -> None:
        mock_client = MagicMock(spec=socket.socket)
        mock_client.fileno.return_value = 10
        cast(MagicMock, self.session.conn.accept).return_value = (
            mock_client,
            ("127.0.0.1", 4321),
        )

        with self.assertLogs("slippers", level="DEBUG") as log_ctx:
            self.session.read()

        self.assertEqual(log_ctx.records[0].msg, "127.0.0.1:4321 (10) connected")
        self.mock_selector.register.assert_called_once_with(
            mock_client, EVENT_READ | EVENT_WRITE, ANY
        )
        client_session = self.mock_selector.register.call_args.args[2]
        self.assertIsInstance(client_session, ClientSession)


class ClientSessionTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.session = ClientSession(
            conn=self.mock_conn,
            addr=("127.0.0.1", 4321),
            selector=self.mock_selector,
            proxy="socks5://foo:bar@my-socks-server.net:1080",
        )

    @patch("slippers.socket.socket")
    def test_connect_proxy(self, mock_socket):
        mock_conn = MagicMock()
        mock_socket.return_value = mock_conn

        self.session.connect_proxy()
        mock_conn.connect.assert_called_once_with(("my-socks-server.net", 1080))
        self.mock_selector.register.assert_called_once_with(
            mock_conn, EVENT_READ | EVENT_WRITE, ANY
        )
        proxy_session = self.mock_selector.register.call_args.args[2]
        self.assertIsInstance(proxy_session, ProxySession)
        self.assertEqual(proxy_session.username, "foo")
        self.assertEqual(proxy_session.password, "bar")
        self.assertEqual(proxy_session.downstream, self.session)

    def test_stage_method_selection(self) -> None:
        # NOOP without at least two bytes
        self.session.stage_method_selection()
        self.assertEqual(self.session.out_buff, b"")

        # Enough packets to check VERSION and NMETHODS fields, but not enough
        # to get the methods
        self.session.in_buff = METH_SELECT_REQ[:2]
        self.session.stage_method_selection()
        self.assertEqual(self.session.in_buff, METH_SELECT_REQ[:2])
        self.assertEqual(self.session.out_buff, b"")

        self.session.in_buff = METH_SELECT_REQ
        with patch.object(self.session, "connect_proxy") as mock_connect_proxy:
            self.session.stage_method_selection()
        self.assertEqual(self.session.in_buff, b"")
        self.assertEqual(self.session.out_buff, METH_SELECT_RES)
        self.assertEqual(self.session.stage, self.session.stage_tunnel)
        mock_connect_proxy.assert_called_once()

    def test_stage_method_selection_invalid(self) -> None:
        # Invalid version
        self.session.in_buff = b"\x04\x01\x00"
        self.session.stage_method_selection()
        self.assertTrue(self.session.closed)

    def test_stage_method_selection_unsupported_methods(self) -> None:
        # Only NO_AUTH (0x00) is supported for the local server
        self.session.in_buff = b"\x05\x02\x01\x02"
        self.session.stage_method_selection()
        self.assertEqual(self.session.in_buff, b"")
        self.assertEqual(self.session.out_buff, METH_SELECT_RES_NOT_ACCEPTABLE)
        self.assertTrue(self.session.closed)

    def test_stage_tunnel(self) -> None:
        self.session.upstream = MagicMock(spec=ProxySession, out_buff=b"")
        self.session.stage_tunnel()
        self.assertEqual(self.session.in_buff, b"")
        self.assertEqual(self.session.upstream.out_buff, b"")

        self.session.in_buff = b"arbitrary data"
        self.session.stage_tunnel()
        self.assertEqual(self.session.in_buff, b"")
        self.assertEqual(self.session.upstream.out_buff, b"arbitrary data")


class ProxySessionTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        downstream = MagicMock(
            spec=ClientSession,
            addr=("127.0.0.1", 4321),
            conn=MagicMock(),
            fd=10,
            closed=False,
            downstream=None,
        )
        self.session = ProxySession(
            conn=self.mock_conn,
            addr=("my-socks-server.net", 1080),
            selector=self.mock_selector,
            username="foo",
            password="bar",
            downstream=downstream,
        )
        downstream.upstream = self.session

    def test_write_while_downstream_closed(self) -> None:
        self.session.downstream.closed = True
        self.session.out_buff = b"hello world"
        cast(MagicMock, self.session.conn.send).return_value = len(
            self.session.out_buff
        )

        # flushes out anything in the out_buff then closes
        self.session.write()
        self.mock_conn.send.asssert_called_once_with(b"hello world")
        self.assertEqual(self.session.out_buff, b"")
        self.assertTrue(self.session.closed)

    def test_stage_auth(self) -> None:
        # Needs two bytes
        self.session.out_buff = b""
        self.session.stage_auth()
        self.assertEqual(self.session.out_buff, b"")

        self.session.in_buff = METH_SELECT_AUTH_RES
        self.session.stage_auth()
        self.assertEqual(self.session.in_buff, b"")
        self.assertEqual(self.session.out_buff, b"\x01\x03foo\x03bar")
        self.assertEqual(self.session.stage, self.session.stage_verify)

    def test_stage_auth_invalid(self) -> None:
        # non user/pass auth selection
        self.session.in_buff = b"\x05\x01"
        self.session.stage_auth()
        self.assertTrue(self.session.closed)
        self.assertTrue(self.session.downstream.closed)


class UtilityTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.conns = socket.socketpair()
        for conn in self.conns:
            self.addCleanup(conn.close)

    @patch("slippers.sys.exit")
    def test_close(self, mock_exit) -> None:
        selector = DefaultSelector()

        server_session = ServerSession(
            conn=self.conns[0],
            addr=("127.0.0.1", 1080),
            selector=self.mock_selector,
            proxy="socks5://foo:bar@my-socks-server.net:1080",
        )

        client_session = ClientSession(
            conn=self.conns[1],
            addr=("127.0.0.1", 4321),
            selector=self.mock_selector,
            proxy="socks5://foo:bar@my-socks-server.net:1080",
        )

        selector.register(
            server_session.conn,
            EVENT_READ,
            server_session,
        )
        selector.register(client_session.conn, EVENT_READ | EVENT_WRITE, client_session)

        close(selector, server_session, signal.SIGTERM, MagicMock())

        self.assertIsNone(selector.get_map())
        self.assertTrue(server_session.closed)
        self.assertTrue(client_session.closed)
        mock_exit.assert_called_once()
