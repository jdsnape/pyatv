"""Connection abstraction for Companion protocol."""
import asyncio
import logging
from enum import Enum
from collections import deque
import socket
from typing import Optional, Tuple

from pyatv import exceptions
from pyatv.support import chacha20, log_binary
from pyatv.companion import opack

_LOGGER = logging.getLogger(__name__)

AUTH_TAG_LENGTH = 16
HEADER_LENGTH = 4


# pylint: disable=invalid-name
class FrameType(Enum):
    """Frame type values."""

    Unknown = 0
    NoOp = 1
    PS_Start = 3
    PS_Next = 4
    PV_Start = 5
    PV_Next = 6
    U_OPACK = 7
    E_OPACK = 8
    P_OPACK = 9
    PA_Req = 10
    PA_Rsp = 11
    SessionStartRequest = 16
    SessionStartResponse = 17
    SessionData = 18
    FamilyIdentityRequest = 32
    FamilyIdentityResponse = 33
    FamilyIdentityUpdate = 34


#  pylint: enable=invalid-name


class CompanionConnection(asyncio.Protocol):
    """Remote connection to a Companion device."""

    def __init__(self, loop: asyncio.AbstractEventLoop, host: str, port: int) -> None:
        """Initialize a new CompanionConnection instance."""
        self.loop = loop
        self.host = str(host)
        self.port = port
        self.transport = None
        self._buffer: bytes = b""
        self._chacha: Optional[chacha20.Chacha20Cipher] = None
        self._queue: deque = deque()
        self._async_queue = deque()
        self.message_received = asyncio.Event()

    @property
    def connected(self) -> bool:
        """If a connection is open or not."""
        return self.transport is not None

    async def connect(self) -> None:
        """Connect to device."""
        await self.loop.create_connection(lambda: self, self.host, self.port)
        # Set TCP keepalive so the connection doesn't get closed
        self.transport.get_extra_info('socket').setsockopt(
            socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.transport.get_extra_info('socket').setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
        self.transport.get_extra_info('socket').setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
        self.transport.get_extra_info('socket').setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

    def close(self) -> None:
        """Close connection to device."""
        _LOGGER.debug("Closing connection")
        if self.transport:
            self.transport.close()
            self.transport = None

    def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
        """Enable encryption with the specified keys."""
        self._chacha = chacha20.Chacha20Cipher(output_key, input_key, nonce_length=12)

    async def exchange(
        self, frame_type: FrameType, data: bytes, timeout: int
    ) -> Tuple[bytes, bytes]:
        """Send message and wait for response."""
        semaphore = asyncio.Semaphore(value=0)
        self._queue.append([None, frame_type, data, semaphore])

        if len(self._queue) == 1:
            self._send_first_in_queue()

        try:
            await asyncio.wait_for(semaphore.acquire(), timeout)
        except Exception:
            # Note here: This will break if the response is just late, not sure how to
            # deal with that as there are no identifier in the message that can be used
            # to match response
            self._queue.popleft()
            self._send_first_in_queue()
            raise

        response = self._queue.popleft()[0]
        log_binary(_LOGGER, "Recv data", Data=response)

        header, data = response[0:4], response[4:]

        if self._chacha:
            data = self._chacha.decrypt(data, aad=header)
            log_binary(_LOGGER, "<< Receive data", Header=header, Decrypted=data)

        # If anyone has a pending request, make sure to send it
        self._send_first_in_queue()

        return header, data

    def _send_first_in_queue(self) -> None:
        if self.transport is None:
            raise exceptions.InvalidStateError("not connected")

        if not self._queue:
            return

        _, frame_type, data, _ = self._queue[0]

        log_binary(
            _LOGGER, ">> Send data", FrameType=bytes([frame_type.value]), Data=data
        )

        payload_length = len(data) + (AUTH_TAG_LENGTH if self._chacha else 0)
        header = bytes([frame_type.value]) + payload_length.to_bytes(3, byteorder="big")

        if self._chacha:
            data = self._chacha.encrypt(data, aad=header)
            log_binary(_LOGGER, ">> Send", Header=header, Encrypted=data)

        self.transport.write(header + data)

    async def listen(self):
        while True:
            # This could just be waiting on the queue? Not sure if that blocks
            await self.message_received.wait()
            while self._async_queue:
                response = self._async_queue.popleft()
                _LOGGER.info(f"Processing {len(response)} encrypted bytes")
                header, data = response[0:4], response[4:]
                if self._chacha:
                    data = self._chacha.decrypt(data, aad=header)
                    log_binary(_LOGGER, "Receive msg", Header=header, Decrypted=data)
                    # TODO check it's actually OPACK here
                    unpacked_object, _ = opack.unpack(data)
                    _LOGGER.debug("Receive OPACK: %s", unpacked_object)
                else:
                    _LOGGER.error("Received data but no encryption established")

            self.message_received.clear()

    def connection_made(self, transport):
        """Handle that connection was eatablished."""
        _LOGGER.debug("Connected to companion device")
        self.transport = transport

    def data_received(self, data):
        """Handle data received from companion."""
        self._buffer += data
        log_binary(_LOGGER, "Received data", Data=data)

        payload_length = HEADER_LENGTH + int.from_bytes(data[1:4], byteorder="big")
        if len(self._buffer) < payload_length:
            _LOGGER.debug(
                "Require %d bytes but only %d in buffer",
                len(self._buffer),
                payload_length,
            )
            return

        data = self._buffer[0:payload_length]
        self._buffer = self._buffer[payload_length:]

        if self._queue:
            receiver = self._queue[0]
            receiver[0] = data
            receiver[3].release()
        else:
            self._async_queue.append(data)
            self.message_received.set()
            log_binary(_LOGGER, "Received asynchronous message", Data=data)

    @staticmethod
    def error_received(exc):
        """Error received from companion."""
        _LOGGER.debug("Connection error: %s", exc)

    def connection_lost(self, exc):
        """Handle that connection was lost from companion."""
        _LOGGER.debug("Connection lost to remote device: %s", exc)
        self.transport = None
