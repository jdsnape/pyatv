"""Various network utility helpers."""

from ipaddress import IPv4Address, IPv4Interface
import logging
import platform
import socket
import struct
from typing import List, Optional

from aiohttp import ClientSession
import netifaces

from pyatv import exceptions
from pyatv.support import log_binary

_LOGGER = logging.getLogger(__name__)


# This timeout is rather long and that is for a reason. If a device is sleeping, it
# automatically wakes up when a service is requested from it. Up to 20 seconds or so
# have been seen. So to deal with that, keep this high.
DEFAULT_TIMEOUT = 25.0  # Seconds


class ClientSessionManager:
    """Manages an aiohttp ClientSession instance."""

    def __init__(self, session: ClientSession, should_close: bool) -> None:
        """Initialize a new ClientSessionManager."""
        self._session = session
        self._should_close = should_close

    @property
    def session(self) -> ClientSession:
        """Return client session."""
        return self._session

    async def close(self) -> None:
        """Close session."""
        if self._should_close:
            await self.session.close()


async def create_session(
    session: Optional[ClientSession] = None,
) -> ClientSessionManager:
    """Create aiohttp ClientSession manged by pyatv."""
    return ClientSessionManager(session or ClientSession(), session is None)


def unused_port() -> int:
    """Return a port that is unused on the current host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def mcast_socket(address: Optional[str], port: int = 0) -> socket.socket:
    """Create a multicast capable socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("b", 10))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, True)

    if hasattr(socket, "SO_REUSEPORT"):
        # FIXME: On windows, SO_REUSEPORT is not available and pylint is still not able
        # to detect that it has been checked with hasattr above:
        # https://github.com/PyCQA/pylint/issues/801
        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEPORT, 1  # pylint: disable=no-member
        )

    if address is not None:
        sock.setsockopt(
            socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address)
        )
        try:
            membership = socket.inet_aton("224.0.0.251") + socket.inet_aton(address)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        except OSError:
            _LOGGER.exception("failed to join")

    _LOGGER.debug("Binding on %s:%d", address or "*", port)
    sock.bind((address or "", port))
    return sock


def get_local_address_reaching(dest_ip: IPv4Address) -> Optional[IPv4Address]:
    """Get address of a local interface within same subnet as provided address."""
    for iface in netifaces.interfaces():
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            iface = IPv4Interface(addr["addr"] + "/" + addr["netmask"])
            if dest_ip in iface.network:
                return iface.ip
    return None


def get_private_addresses() -> List[IPv4Address]:
    """Get private (RFC1918 + loopback) addresses from all interfaces."""
    addresses: List[IPv4Address] = []
    for iface in netifaces.interfaces():
        for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            ipaddr = IPv4Address(addr["addr"])
            if ipaddr.is_private:
                addresses.append(ipaddr)
    return addresses


# Reference: https://stackoverflow.com/a/14855726
def tcp_keepalive(sock) -> None:
    """Configure keep-alive on a socket."""
    current_platform = platform.system()

    if not hasattr(socket, "SO_KEEPALIVE"):
        raise exceptions.NotSupportedError("System does not support keep-alive")

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    # Default values are 1s idle time, 5s interval and 4 fails
    keepalive_options = {
        "TCP_KEEPIDLE": 1,
        "TCP_KEEPINTVL": 5,
        "TCP_KEEPCNT": 4,
    }

    for option_name, value in keepalive_options.items():
        try:
            option = getattr(socket, option_name)
        except AttributeError as ex:
            if current_platform == "Darwin" and option_name == "TCP_KEEPIDLE":
                # TCP_KEEPALIVE will hopefully be available at some point,
                # (https://bugs.python.org/issue34932) but until then the value is
                # hardcoded.
                # https://github.com/apple/darwin-xnu/blob/
                #   0a798f6738bc1db01281fc08ae024145e84df927/bsd/netinet/tcp.h#L206
                option = 0x10
            else:
                raise exceptions.NotSupportedError(
                    f"Option {option_name} is not supported"
                ) from ex
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError as ex:
            raise exceptions.NotSupportedError(
                f"Unable to set {option_name} ({option:#x}) on {sock}: {ex}"
            )

    _LOGGER.debug("Configured keep-alive on %s (%s)", sock, current_platform)


class HttpSession:
    """This class simplifies GET/POST requests."""

    def __init__(self, client_session: ClientSession, base_url: str):
        """Initialize a new HttpSession."""
        self._session = client_session
        self.base_url = base_url

    async def get_data(self, path, headers=None, timeout=None):
        """Perform a GET request."""
        url = self.base_url + path
        _LOGGER.debug("GET URL: %s", url)
        resp = None
        try:
            resp = await self._session.get(
                url,
                headers=headers,
                timeout=DEFAULT_TIMEOUT if timeout is None else timeout,
            )
            _LOGGER.debug(
                "Response: status=%d, headers=[%s]",
                resp.status,
                ", ".join([f"{key}={value}" for key, value in resp.headers.items()]),
            )
            if resp.content_length is not None:
                resp_data = await resp.read()
                log_binary(_LOGGER, "<< GET", Data=resp_data)
            else:
                resp_data = None
            return resp_data, resp.status
        except Exception as ex:
            if resp is not None:
                resp.close()
            raise ex
        finally:
            if resp is not None:
                await resp.release()

    async def post_data(self, path, data=None, headers=None, timeout=None):
        """Perform a POST request."""
        url = self.base_url + path
        _LOGGER.debug("POST URL: %s", url)
        log_binary(_LOGGER, ">> POST", Data=data)

        resp = None
        try:
            resp = await self._session.post(
                url,
                headers=headers,
                data=data,
                timeout=DEFAULT_TIMEOUT if timeout is None else timeout,
            )
            _LOGGER.debug(
                "Response: status=%d, headers=[%s]",
                resp.status,
                ", ".join([f"{key}={value}" for key, value in resp.headers.items()]),
            )
            if resp.content_length is not None:
                resp_data = await resp.read()
            else:
                resp_data = None
                log_binary(_LOGGER, "<< POST", Data=resp_data)
            return resp_data, resp.status
        except Exception as ex:
            if resp is not None:
                resp.close()
            raise ex
        finally:
            if resp is not None:
                await resp.release()
