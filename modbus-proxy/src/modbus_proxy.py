#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modbus Proxy - A Modbus TCP/RTU proxy server with unit ID remapping

This file is part of the modbus-proxy project

Copyright (c) 2020-2021 Tiago Coutinho
Distributed under the GPLv3 license. See LICENSE for more info.
"""
# pylint: disable=too-many-lines,broad-exception-caught,too-many-branches,too-many-statements,too-many-locals
# temporary exclusions to be fixed later

import asyncio
import pathlib
import argparse
import warnings
import contextlib
import logging
import logging.config
import os
import stat
from urllib.parse import urlparse, ParseResult
import ast
import types
import struct
import sys
import traceback


__version__ = "2.3.0"

# Changelog:
# 2.3.0 - Added Reverse TCP mode with UDP connection start
# 0.8.5 - Normalize RTU device path: ensure absolute path and resolve symlinks
# 0.8.4 - Fix RTU over TCP communication issue, improve format detection
#         - Fixed assumption that HA always expects TCP format responses
#         - Added intelligent format detection for client requests (TCP vs RTU over TCP)
#         - Enhanced _transform_reply to support both TCP and RTU over TCP response formats
#         - Optimized format detection to avoid duplicate processing
#         - Now properly supports RTU over TCP -> RTU over TCP communication
# 0.8.3 - Fix IPv6 binding support
# 0.8.2 - Add RTU(over)TCP, fix RTU issues
# 0.8.1 - Enhanced logging system with TRACE level, improved RTU support with asyncio serial
#         - Added custom TRACE logging level for proxy activity overview
#         - Improved RTU/Serial support with pyserial-asyncio
#         - Enhanced IP tracking and request counting
#         - Better device permission handling and udev integration
#         - Improved error handling and connection management
# 0.8.0 - Original version from tiagocoutinho/modbus-proxy


DEFAULT_LOG_CONFIG = {
    "version": 1,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)8s %(name)s: %(message)s"},
        "detailed": {"format": "%(asctime)s %(levelname)8s [%(name)s] %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "detailed"}
    },
    "root": {"handlers": ["console"], "level": "INFO"},
}

log = logging.getLogger("modbus-proxy")


def parse_url(url: str) -> ParseResult:
    """Parse a URL and ensure it has a scheme and hostname."""
    if "://" not in url:
        url = f"tcp://{url}"
    result = urlparse(url)
    if not result.hostname:
        url = result.geturl().replace("://", "://0")
        result = urlparse(url)
    return result


def modbus_crc(data: bytes) -> int:
    """
    Calculate Modbus RTU CRC-16 for the given data.

    Args:
        data: Bytes to calculate CRC for (UID + function code + payload)

    Returns:
        CRC value as integer (0-65535)
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc = crc >> 1
    return crc


def module_from_string(
    code: str, name: str = "<string>", extra_globals: dict | None = None
) -> types.ModuleType:
    """Import a module from a string containing Python code."""
    # syntax check -> raises SyntaxError with location if bad
    ast.parse(code, filename=name)
    mod = types.ModuleType(name)
    mod.__file__ = name
    if extra_globals:
        mod.__dict__.update(extra_globals)  # inject environment functions here
    sys.modules[name] = mod
    try:
        exec(compile(code, name, "exec"), mod.__dict__)  # pylint: disable=exec-used
    except Exception:
        traceback.print_exc()
        raise
    return mod


class Connection:  # pylint: disable=too-many-instance-attributes
    """ModBus Connection Handler Base Class"""

    def __init__(self, name, reader, writer):
        self.name = name
        self.reader = reader
        self.writer = writer
        self.log = log.getChild(name)
        self.serial_reader = None
        self.serial_writer = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, tb):
        await self.close()

    @property
    def opened(self):
        """Check if connection is opened."""
        # pylint: disable=no-member
        if hasattr(self, "modbus_type") and self.modbus_type == "rtu":
            # Check RTU/Serial connection
            if hasattr(self, "serial_writer"):
                return (
                    self.serial_writer is not None
                    and not self.serial_writer.is_closing()
                    and not self.serial_reader.at_eof()
                )
            if hasattr(self, "serial"):
                return self.serial is not None and self.serial.is_open
            return False

        # Check TCP connection
        return (
            self.writer is not None
            and not self.writer.is_closing()
            and not self.reader.at_eof()
        )

    async def close(self):  # pylint: disable=too-many-branches
        """Close the connection."""
        # pylint: disable=no-member
        if hasattr(self, "modbus_type") and self.modbus_type == "rtu":
            # Close RTU/Serial connection
            if hasattr(self, "serial_writer"):
                self.log.info("closing RTU connection...")
                try:
                    self.serial_writer.close()
                    await self.serial_writer.wait_closed()
                except Exception as error:
                    self.log.info("failed to close RTU: %r", error)
                else:
                    self.log.info("RTU connection closed")
                finally:
                    self.serial_reader = None
                    self.serial_writer = None
            elif hasattr(self, "serial"):
                self.log.info("closing RTU connection...")
                try:
                    self.serial.close()  # pylint: disable=access-member-before-definition
                except Exception as error:
                    self.log.info("failed to close RTU: %r", error)
                else:
                    self.log.info("RTU connection closed")
                finally:
                    self.serial = None  # pylint: disable=attribute-defined-outside-init
        elif self.writer is not None:
            # Close TCP connection
            self.log.info("closing connection...")
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as error:
                self.log.info("failed to close: %r", error)
            else:
                self.log.info("connection closed")
            finally:
                self.reader = None
                self.writer = None
        # No intermediate UDP attributes are stored on the object anymore.
        # Reverse-TCP listener and UDP transport are created as local variables
        # during `open()` and cleaned up there.

    async def _write(self, data):
        # pylint: disable=no-member

        if hasattr(self, "modbus_type") and self.modbus_type == "rtu":
            # RTU/Serial write
            if hasattr(self, "serial_writer"):
                # Async serial
                self.log.debug(f"[RTU:{self.device}] → Request: %d bytes", len(data))
                self.serial_writer.write(data)
                await self.serial_writer.drain()
            elif hasattr(self, "serial"):
                # Sync serial fallback
                self.log.debug(f"[RTU:{self.device}] → Request: %d bytes", len(data))
                self.serial.write(data)
                self.serial.flush()
        else:
            # TCP write
            self.log.debug(
                f"[TCP:{self.modbus_host}:{self.modbus_port}] → Request: %d bytes",
                len(data),
            )
            self.writer.write(data)
            await self.writer.drain()

    async def write(self, data):
        """Write ModBus message to server ie request"""
        try:
            await self._write(data)
        except Exception as error:
            self.log.error("writting error: %r", error)
            await self.close()
            return False
        return True

    async def _read(self):
        """Read ModBus TCP message from server ie response"""
        # Handle Modbus TCP, RTU and ASCII
        # pylint: disable=no-member
        if hasattr(self, "modbus_type") and self.modbus_type in ["rtu", "rtutcp"]:
            # RTU/Serial Modbus - different protocol
            return await self._read_rtu()

        # TCP Modbus
        header = await self.reader.readexactly(6)
        size = int.from_bytes(header[4:], "big")
        reply = header + await self.reader.readexactly(size)

        self.log.debug(
            f"[TCP:{self.modbus_host}:{self.modbus_port}] ← Response: %d bytes",
            len(reply),
        )

        # Enhanced debug logging for modbus data
        if self.log.isEnabledFor(logging.DEBUG) and len(reply) >= 7:
            self._log_modbus_message(reply, "received")

        return reply

    async def _read_rtu(self):
        """Read ModBus RTU message from server ie response"""
        # RTU protocol: [slave_id][function_code][data][crc_low][crc_high]
        # We need to read byte by byte to detect frame boundaries

        # Use appropriate reader based on connection type
        reader = self.serial_reader if hasattr(self, "serial_reader") else self.reader

        # Read first byte (slave ID)
        slave_id = await reader.readexactly(1)

        # Read function code
        function_code = await reader.readexactly(1)

        # Read data based on function code
        data = b""
        if function_code[0] in [0x01, 0x02, 0x03, 0x04]:  # Read functions
            # Read byte count, then (address (2 bytes) + value (2 bytes)) times byte count/4
            byte_count = await reader.readexactly(1)
            data = byte_count + await reader.readexactly(byte_count[0])
        elif function_code[0] in [
            0x05,
            0x06,
            0x0F,
            0x10,
        ]:  # Write single, Write multiple
            # Read address (2 bytes) + value (2 bytes)
            data = await reader.readexactly(4)

        # Read CRC (2 bytes)
        crc = await reader.readexactly(2)

        # Combine into RTU frame
        rtu_frame = slave_id + function_code + data + crc

        # pylint: disable=no-member
        if hasattr(self, "modbus_type") and self.modbus_type == "rtu":
            self.log.debug(f"[RTU:{self.device}] ← Response: %d bytes", len(rtu_frame))
        else:
            self.log.debug(
                f"[RTUoverTCP:{self.modbus_host}:{self.modbus_port}] ← Response: %d bytes",
                len(rtu_frame),
            )

        # Enhanced debug logging for RTU data
        if self.log.isEnabledFor(logging.DEBUG) and len(rtu_frame) >= 4:
            self._log_rtu_message(rtu_frame, "received")

        return rtu_frame

    async def read(self):
        """Read ModBus message from server ie response"""
        try:
            return await self._read()
        except asyncio.IncompleteReadError as error:
            if error.partial:
                self.log.error("reading error: %r", error)
            else:
                self.log.info("client closed connection")
            await self.close()
        except Exception as error:
            self.log.error("reading error: %r", error)
            await self.close()

    def _log_modbus_message(self, data, direction):
        # pylint: disable=too-many-nested-blocks,too-many-branches,too-many-locals
        """Enhanced logging for modbus messages with parsed details"""
        if len(data) < 7:
            return

        try:

            # Parse MBAP header
            transaction_id, _, _, unit_id = struct.unpack(">HHHB", data[:7])

            if len(data) > 7:
                function_code = data[7]
                pdu = data[8:]

                # Log basic info
                self.log.debug(
                    f"{direction}: TxID={transaction_id}, Unit={unit_id}, FC={function_code:02X}"
                )

                # Parse function-specific data for read responses
                if (
                    direction == "received"
                    and function_code in [0x01, 0x02, 0x03, 0x04]
                    and len(pdu) > 0
                ):
                    byte_count = pdu[0]
                    if len(pdu) >= 1 + byte_count:
                        values_data = pdu[1 : 1 + byte_count]

                        if function_code in [0x01, 0x02]:  # Coils/Discrete Inputs
                            values = []
                            for i, byte_val in enumerate(values_data):
                                for bit in range(8):
                                    if i * 8 + bit < byte_count * 8:
                                        values.append((byte_val >> bit) & 1)
                            self.log.debug(
                                f"Values: {values[:16]}{'...' if len(values) > 16 else ''}"
                            )

                        elif function_code in [0x03, 0x04]:  # Holding/Input Registers
                            values = []
                            for i in range(0, len(values_data), 2):
                                if i + 1 < len(values_data):
                                    value = struct.unpack(">H", values_data[i : i + 2])[
                                        0
                                    ]
                                    values.append(value)
                            self.log.debug(
                                f"Registers: {values[:8]}{'...' if len(values) > 8 else ''}"
                            )

        except Exception as e:
            self.log.debug(f"Failed to parse modbus message: {e}")

    def _log_rtu_message(self, data, direction):
        # pylint: disable=too-many-nested-blocks,too-many-branches
        """Enhanced logging for RTU modbus messages with parsed details"""
        if len(data) < 4:
            return

        try:
            # Parse RTU frame: [slave_id][function_code][data][crc_low][crc_high]
            slave_id = data[0]
            function_code = data[1]
            rtu_data = data[2:-2]  # Exclude CRC
            # crc = data[-2:]

            # Log basic info
            self.log.debug(f"{direction} RTU: Slave={slave_id}, FC={function_code:02X}")

            # Parse function-specific data for read responses
            if (
                direction == "received"
                and function_code in [0x01, 0x02, 0x03, 0x04]
                and len(rtu_data) > 1
            ):
                byte_count = rtu_data[0]
                if len(rtu_data) >= 1 + byte_count:
                    values_data = rtu_data[1 : 1 + byte_count]

                    if function_code in [0x01, 0x02]:  # Coils/Discrete Inputs
                        values = []
                        for i, byte_val in enumerate(values_data):
                            for bit in range(8):
                                if i * 8 + bit < byte_count * 8:
                                    values.append((byte_val >> bit) & 1)
                        self.log.debug(
                            f"RTU Values: {values[:16]}{'...' if len(values) > 16 else ''}"
                        )

                    elif function_code in [0x03, 0x04]:  # Holding/Input Registers
                        values = []
                        for i in range(0, len(values_data), 2):
                            if i + 1 < len(values_data):
                                value = struct.unpack(">H", values_data[i : i + 2])[0]
                                values.append(value)
                        self.log.debug(
                            f"RTU Values: {values[:8]}{'...' if len(values) > 8 else ''}"
                        )

            # Parse function-specific data for read responses
            if (
                direction == "received_from_client"
                and function_code in [0x01, 0x02, 0x03, 0x04]
                and len(rtu_data) >= 4
            ):
                values = []
                for i in range(0, len(rtu_data) - 1, 2):
                    value = struct.unpack(">H", rtu_data[i : i + 2])[0]
                    values.append(value)
                self.log.debug(
                    f"RTU Registers: {values[:8]}{'...' if len(values) > 8 else ''}"
                )

        except Exception as e:
            self.log.debug(f"Failed to parse RTU message: {e}")


class Client(Connection):
    """ModBus Client Connection Handler"""

    def __init__(self, reader, writer):
        # Be defensive: peername may be None (e.g. unusual transports).
        peer = writer.get_extra_info("peername")
        if not peer or not isinstance(peer, (list, tuple)) or len(peer) < 2:
            # Fall back to unknown address to avoid raising during construction
            try:
                host = writer.get_extra_info("sockname") or "0.0.0.0"
            except Exception:
                host = "0.0.0.0"
            peer = (host, 0)
        super().__init__(f"Client({peer[0]}:{peer[1]})", reader, writer)
        self.client_ip = peer[0]
        self.client_port = peer[1]
        self.request_count = 0
        self.log.info(
            f"new client connection from {self.client_ip}:{self.client_port} -> to Proxy"
        )

    async def _write(self, data):
        # Enhanced logging for client writes (responses)
        self.log.debug(
            f"[{self.client_ip}:{self.client_port}] → Response: %d bytes", len(data)
        )
        if self.log.isEnabledFor(logging.DEBUG) and len(data) >= 7:
            self._log_modbus_message(data, "sent_to_client")
        self.writer.write(data)
        await self.writer.drain()

    async def _read(self):
        """Read ModBus message from client with auto-detection"""
        # Auto-detect TCP vs RTU over TCP format from Home Assistant

        # Read first 6 bytes to check format
        first_bytes = await self.reader.readexactly(6)

        # Check if it's TCP format by looking at Protocol ID (bytes 2-3)
        protocol_id = int.from_bytes(first_bytes[2:4], "big")

        if protocol_id == 0:
            # TCP format detected: [MBAP Header 6 bytes][Unit ID][Function][Data]
            size = int.from_bytes(first_bytes[4:6], "big")
            reply = first_bytes + await self.reader.readexactly(size)

            self.request_count += 1
            self.log.debug(
                f"[{self.client_ip}:{self.client_port}] ← TCP Request #{self.request_count}: %d bytes",
                len(reply),
            )

            if self.log.isEnabledFor(logging.DEBUG) and len(reply) >= 7:
                self._log_modbus_message(reply, "received_from_client")

            return reply

        # RTU over TCP format detected: [Unit ID][Function][Data][CRC]
        # first_bytes contains: [Unit ID][Function][4 bytes of data/address]
        unit_id = first_bytes[0]
        function_code = first_bytes[1]

        # Read remaining data based on function code
        remaining_data = first_bytes[2:]  # Already have 4 bytes

        if function_code in [0x01, 0x02, 0x03, 0x04]:  # Read functions
            # Format: [Unit][Func][Address 2][Count 2][CRC 2] = 8 bytes total
            # We have 6 bytes, need 2 more (CRC)
            remaining_data += await self.reader.readexactly(2)
        elif function_code in [0x05, 0x06]:  # Write single
            # Format: [Unit][Func][Address 2][Value 2][CRC 2] = 8 bytes total
            # We have 6 bytes, need 2 more (CRC)
            remaining_data += await self.reader.readexactly(2)
        elif function_code in [0x0F, 0x10]:  # Write multiple
            # We need to read byte count first, then data, then CRC
            byte_count = remaining_data[2]  # 5th byte overall
            if len(remaining_data) < 3 + byte_count + 2:  # Need more data
                additional_needed = 3 + byte_count + 2 - len(remaining_data)
                remaining_data += await self.reader.readexactly(additional_needed)
        else:
            # Unknown function, try to read 2 more bytes (CRC)
            remaining_data += await self.reader.readexactly(2)

        reply = bytes([unit_id, function_code]) + remaining_data

        self.request_count += 1
        self.log.debug(
            f"[{self.client_ip}:{self.client_port}] ← RTU over TCP Request #{self.request_count}: %d bytes",
            len(reply),
        )

        if self.log.isEnabledFor(logging.DEBUG) and len(reply) >= 4:
            self._log_rtu_message(reply, "received_from_client")

        return reply


class ModBus(Connection):  # pylint: disable=too-many-instance-attributes
    """ModBus Server Connection Handler"""

    def __init__(self, config):
        modbus = config["modbus"]
        url = parse_url(modbus["url"])
        bind = parse_url(config["listen"]["bind"])

        # Ensure base Connection init runs to set up logging; helpers will
        # update `self.name` and `self.log` with more specific names.
        super().__init__("ModBus", None, None)

        self.port = 502 if bind.port is None else bind.port
        self.timeout = modbus.get("timeout", None)
        self.connection_time = modbus.get("connection_time", 0)
        self.unit_id_remapping = config.get("unit_id_remapping") or {}

        # Determine if it's RTU or TCP based on URL scheme and delegate
        if url.scheme == "rtu":
            self._init_rtu(url, modbus)
        elif url.scheme == "rtutcp":
            self._init_rtutcp(url)
        elif url.scheme == "rtcpmrtu":
            self._init_rtcpmrtu(url, modbus)
        else:
            self._init_tcp(url)

        # Handle IPv6 support: "0" should bind to all interfaces (IPv4 + IPv6)
        if bind.hostname == "0":
            self.host = None  # None binds to all interfaces (IPv4 + IPv6)
        else:
            self.host = bind.hostname
        self.server = None
        self._reverse_tcp_conn_future = None
        self.lock = asyncio.Lock()

    def _init_rtu(self, url, modbus):
        """Initialize RTU-specific settings."""
        self.modbus_type = "rtu"
        # Use the raw path from URL; ensure it is absolute
        raw_path = url.path or ""
        # If URL gives an empty path (unlikely), allow fallback from hostname
        if not raw_path and url.hostname:
            raw_path = url.hostname
        # Ensure leading slash
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        # Normalize and resolve symlinks if present
        device_path = os.path.abspath(os.path.realpath(raw_path))
        # Keep a user-friendly name for logs (basename)
        device_name = os.path.basename(device_path)
        self.name = f"ModBus(RTU:{device_name})"
        self.log = log.getChild(self.name)
        self.device = device_path

        self.baudrate = modbus.get("baudrate", 9600)
        self.databits = modbus.get("databits", 8)
        self.stopbits = modbus.get("stopbits", 1)
        self.parity = modbus.get("parity", "N")

    def _init_rtutcp(self, url):
        """Initialize RTU-over-TCP settings."""
        self.modbus_type = "rtutcp"
        self.name = f"ModBus({url.hostname}:{url.port})"
        self.log = log.getChild(self.name)
        self.modbus_host = url.hostname
        self.modbus_port = url.port

    def _init_rtcpmrtu(self, url, modbus):
        """Initialize rtcpmrtu (reverse TCP + UDP preflight) settings."""
        self.modbus_type = "rtcpmrtu"
        self.name = f"ModBus({url.hostname}:{url.port})"
        self.log = log.getChild(self.name)
        self.modbus_host_udp = url.hostname
        self.modbus_port_udp = url.port
        self.modbus_host = self.modbus_host_udp
        self.modbus_port = self.modbus_port_udp

        # Configurable MBAP/protocol override (accept int or hex string)
        protocol_remap = modbus.get("protocol_remapping", modbus.get("mbap_protocol", None))
        if isinstance(protocol_remap, str):
            try:
                self.protocol_remapping = int(protocol_remap, 0)
            except Exception:
                # support plain hex without 0x
                try:
                    self.protocol_remapping = int(protocol_remap, 16)
                except Exception:
                    self.protocol_remapping = None
        else:
            self.protocol_remapping = int(protocol_remap) if protocol_remap is not None else None

        # Routing bytes (hex string expected). If not provided, default to empty bytes
        routing = modbus.get("routing_bytes", modbus.get("routing", None))
        if routing:
            try:
                self.routing_bytes = bytes.fromhex(routing)
            except Exception:
                self.routing_bytes = b""
        else:
            self.routing_bytes = b""

        # Read connect templates from rtcpmrtu_session_start_* keys
        self.rtcpmrtu_session_start_request = modbus.get("rtcpmrtu_session_start_request")
        self.rtcpmrtu_session_start_response = modbus.get("rtcpmrtu_session_start_response")
        self.rtcpmrtu_session_start_timeout = modbus.get("rtcpmrtu_session_start_timeout", self.timeout or 5)

        # Optional explicit port to listen for reverse-TCP connections.
        try:
            self.rtcp_listen_port = int(modbus.get("rtcp_listen_port", 0) or 0)
        except Exception:
            self.rtcp_listen_port = 0

    def _init_tcp(self, url):
        """Initialize TCP settings."""
        self.modbus_type = "tcp"
        self.name = f"ModBus({url.hostname}:{url.port})"
        self.log = log.getChild(self.name)
        self.modbus_host = url.hostname
        self.modbus_port = url.port

    @property
    def address(self):
        """Get the server's bound address."""
        if self.server is not None:
            return self.server.sockets[0].getsockname()
        return None

    async def open(self):
        """Open the connection if required"""
        if self.modbus_type == "rtu":
            self.log.info(f"connecting to RTU device {self.device}...")

            # Check device permissions and existence
            if not os.path.exists(self.device):
                raise FileNotFoundError(f"Serial device {self.device} not found")

            # Check device existence and type
            if not os.path.exists(self.device):
                raise FileNotFoundError(f"Serial device {self.device} not found")

            try:
                device_stat = os.stat(self.device)
                if not stat.S_ISCHR(device_stat.st_mode):
                    raise ValueError(f"{self.device} is not a character device")

                # Check if we have read/write permissions (set by Supervisor)
                if not os.access(self.device, os.R_OK | os.W_OK):
                    self.log.error(
                        f"Insufficient permissions for {self.device}. Check Supervisor device mapping."
                    )
                    raise PermissionError(
                        f"Cannot access {self.device} - check config.yaml devices list"
                    )
            except Exception as e:
                self.log.error(f"Device check failed: {e}")
                raise

            # Use asyncio serial connection
            try:
                # pylint: disable=attribute-defined-outside-init
                import serial_asyncio  # pylint: disable=import-outside-toplevel

                (
                    self.serial_reader,
                    self.serial_writer,
                ) = await serial_asyncio.open_serial_connection(
                    url=self.device,
                    baudrate=self.baudrate,
                    bytesize=self.databits,
                    parity=self.parity,
                    stopbits=self.stopbits,
                    timeout=self.timeout,
                )
                self.log.info(f"connected to RTU device {self.device}!")
            except ImportError:
                # Fallback to synchronous serial if asyncio version not available
                self.log.warning(
                    "pyserial-asyncio not available, using synchronous fallback"
                )
                import serial  # pylint: disable=import-outside-toplevel

                self.serial = serial.Serial(
                    port=self.device,
                    baudrate=self.baudrate,
                    bytesize=self.databits,
                    parity=self.parity,
                    stopbits=self.stopbits,
                    timeout=self.timeout,
                )
                self.log.info(f"connected to RTU device {self.device} (sync mode)!")
        elif self.modbus_type == "rtcpmrtu":
            # Reverse-TCP UDP mode:
            # 1) Create a short-lived UDP endpoint so we know the local address
            # 2) Start an ephemeral TCP listener on that local address
            # 3) Send the `rtcpmrtu_session_start_request` session connect UDP message to the device
            # 4) Wait for the UDP session connect response `rtcpmrtu_session_start_response`
            # 5) Wait for the device to connect back to the ephemeral TCP listener
            # 6) Promote the accepted TCP connection to the active Modbus TCP session
            # pylint: disable=attribute-defined-outside-init
            loop = asyncio.get_running_loop()

            class _UDPProtocol(asyncio.DatagramProtocol):
                def __init__(self, parent_log):
                    self.queue = asyncio.Queue()
                    self.return_addr = None
                    self.log = parent_log
                    self.closed = asyncio.get_running_loop().create_future()

                def connection_made(self, transport):
                    self.transport = transport
                    local = transport.get_extra_info("sockname")
                    sock = transport.get_extra_info("socket")
                    if local:
                        self.return_addr = local
                    elif sock is not None:
                        try:
                            self.return_addr = sock.getsockname()
                        except Exception:
                            self.return_addr = None
                    else:
                        self.return_addr = None
                    try:
                        self.log.info("udp local addr: %s", self.return_addr)
                    except Exception:
                        pass

                def connection_lost(self, exc):
                    # Called when transport is closed
                    if not self.closed.done():
                        self.closed.set_result(None)

                def datagram_received(self, data, addr):
                    try:
                        self.queue.put_nowait((data, addr))
                    except Exception:
                        pass

            bind_host = self.host if self.host is not None else "0.0.0.0"

            # Create UDP endpoint bound to an ephemeral port so we learn our local IP
            udp_transport, udp_protocol = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self.log),
                local_addr=(bind_host, 0),
                remote_addr=(self.modbus_host_udp, self.modbus_port_udp),
            )

            # UDP endpoint created; local address available via protocol

            # Use the UDP endpoint local IP as the address for the TCP listener (if available)
            local_ip = (
                udp_protocol.return_addr[0]
                if getattr(udp_protocol, "return_addr", None)
                else bind_host
            )

            # Prepare a Future that the accept handler will fulfill when the
            # device connects back. Create it here to avoid races between the
            # waiter and the handler (both must reference the same Future).
            # The attribute is pre-declared in the constructor; replace its
            # value with a fresh Future for this open() attempt.
            self._reverse_tcp_conn_future = asyncio.get_running_loop().create_future()

            # Start ephemeral TCP listener that the device will connect to
            async def _accept_handler(reader, writer):
                # Future `self._reverse_tcp_conn_future` is created before
                # starting the listener; assume it exists. If it's already
                # done, this is an extra connection — log and close it.
                if self._reverse_tcp_conn_future is not None and not self._reverse_tcp_conn_future.done():
                    self._reverse_tcp_conn_future.set_result((reader, writer))
                else:
                    try:
                        self.log.error("reverse TCP listener received extra connection, closing it")
                    except Exception:
                        pass
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            tcp_bind_host = None if local_ip in ("0", "0.0.0.0", "0.0.0.0") else local_ip
            # Use configured listen port if provided, otherwise use ephemeral port 0
            port_arg = self.rtcp_listen_port if getattr(self, "rtcp_listen_port", 0) else 0

            # Bind with reuse options to reduce bind failures on fast restarts.
            reverse_tcp_server = await asyncio.start_server(
                _accept_handler,
                tcp_bind_host,
                port_arg,
                reuse_address=True,
                reuse_port=True,
            )
            try:
                listener_sockname = reverse_tcp_server.sockets[0].getsockname()
                listener_port = listener_sockname[1]
            except Exception:
                listener_port = 0

            self.log.info(
                "rtcpmrtu modbustcp listening on %s and reverse TCP listener on %s:%s (waiting for device)",
                bind_host,
                tcp_bind_host or "0.0.0.0",
                listener_port,
            )

            async def _cleanup():
                """Clean up temporary reverse-TCP listener, UDP transport and future."""
                # Close reverse TCP server if present
                nonlocal reverse_tcp_server
                nonlocal udp_transport
                nonlocal udp_protocol
                nonlocal self
                try:
                    if reverse_tcp_server is not None:
                        reverse_tcp_server.close()
                        try:
                            await reverse_tcp_server.wait_closed()
                        except Exception as e:
                            self.log.warning("Failed closing reverse_tcp_server socket: %r", e)
                        reverse_tcp_server = None
                except Exception as e:
                    self.log.warning("Failed closing reverse_tcp_server B: %r", e)
                reverse_tcp_server = None

                # Close UDP transport if present
                try:
                    if udp_transport is not None:
                        udp_transport.close()
                        sock = udp_transport.get_extra_info('socket')  # get underlying socket (may be None)
                        if sock is not None:
                            # Optionally unregister the reader to be extra safe, then close the socket.
                            try:
                                loop.remove_reader(sock.fileno())
                            except Exception:
                                pass
                            try:
                                sock.close()
                            except Exception:
                                pass
                        await udp_protocol.closed
                except Exception as e:
                    self.log.warning("Failed closing udp_transport: %r", e)
                udp_transport = None
                udp_protocol = None

                # Cancel and remove the temporary future if still present
                try:
                    if self._reverse_tcp_conn_future is not None:
                        self._reverse_tcp_conn_future.cancel()
                        # clear reference promptly to avoid accidental reuse
                        self._reverse_tcp_conn_future = None
                except Exception as e:
                    self.log.warning("Failed closing _reverse_tcp_conn_future: %r", e)

            # Helper to render templates using the TCP listener address
            def render_template(tpl: str) -> str:
                mapping = {
                    "HOST": local_ip if local_ip is not None else "0.0.0.0",
                    "PORT": str(listener_port),
                }
                v = tpl.format(**mapping)
                self.log.debug("rtcpmrtu set template: %r -> %r", mapping, v)
                return v

            # If configured, send the preflight session-start request and expect the configured response
            if self.rtcpmrtu_session_start_request and self.rtcpmrtu_session_start_response:
                set_addr_req = render_template(self.rtcpmrtu_session_start_request)
                try:
                    set_addr_req_bytes = bytes.fromhex(set_addr_req)
                except Exception:
                    set_addr_req_bytes = set_addr_req.encode()

                # keep payload exact (no padding)
                udp_transport.sendto(
                    set_addr_req_bytes, (self.modbus_host_udp, self.modbus_port_udp)
                )
                try:
                    data_recv, _ = await asyncio.wait_for(
                        udp_protocol.queue.get(), timeout=self.rtcpmrtu_session_start_timeout
                    )
                except Exception as e:
                    self.log.error("UDP session connect timeout/wait error: %r", e)
                    # Cleanup resources
                    await _cleanup()
                    raise

                expected = render_template(self.rtcpmrtu_session_start_response)
                try:
                    expected_bytes = bytes.fromhex(expected)
                except Exception:
                    expected_bytes = expected.encode()

                if data_recv != expected_bytes:
                    self.log.error(
                        "UDP session connect response mismatch: got %r expected %r",
                        data_recv,
                        expected_bytes,
                    )
                    # Cleanup resources
                    await _cleanup()
                    raise RuntimeError("UDP session connect response mismatch")

            # Wait for the device to connect back to our TCP listener
            try:
                self.log.info("waiting for device to connect back to TCP listener...")
                reader, writer = await asyncio.wait_for(
                    self._reverse_tcp_conn_future,
                    timeout=self.timeout or 30,
                )
            except Exception as e:
                self.log.error("Timeout waiting for device TCP connection: %r", e)
                # Cleanup resources
                await _cleanup()
                raise

            # Promote the accepted TCP connection to active session
            # Close any existing downstream writer first to avoid leaking fds
            try:
                if hasattr(self, "writer") and self.writer is not None:
                    self.log.warning("Closing existing writer")
                    self.writer.close()
                    await self.writer.wait_closed()
            except Exception as e:
                self.log.warning("Failed closing existing writer: %r", e)

            # Set up vars for tcp session
            peer = writer.get_extra_info("peername")
            if peer and len(peer) >= 2:
                self.modbus_host = peer[0]
                self.modbus_port = peer[1]
            self.reader = reader
            self.writer = writer
            self.log.info("Device connected from %s:%s", self.modbus_host, self.modbus_port)

            # Cleanup resources now that connection is established
            await _cleanup()

        else:
            self.log.info(
                f"connecting Proxy to Modbus Device({self.modbus_host}:{self.modbus_port})..."
            )
            self.reader, self.writer = await asyncio.open_connection(
                self.modbus_host, self.modbus_port
            )
            self.log.info(
                f"connected to Device({self.modbus_host}:{self.modbus_port})!"
            )

    async def close(self):
        """Close the connection if required"""
        await super().close()

    async def connect(self):
        """Connection if required"""
        if not self.opened:
            await asyncio.wait_for(self.open(), self.timeout)
            if self.connection_time > 0:
                self.log.info("delay after connect: %s", self.connection_time)
                await asyncio.sleep(self.connection_time)

    async def write_read(self, data, attempts=2):
        """Write then read ModBus message with retries"""
        async with self.lock:
            for i in range(attempts):
                try:
                    await self.connect()
                    coro = self._write_read(data)
                    return await asyncio.wait_for(coro, self.timeout)
                except Exception as error:
                    self.log.error(
                        "%s write_read error [%s/%s]: %r", self.modbus_type, i + 1, attempts, error
                    )
                    await self.close()

    async def _write_read(self, data):
        await self._write(data)
        return await self._read()

    def _transform_request(
        self, request, source_format=None
    ):  # pylint: disable=too-many-branches,too-many-return-statements,too-many-statements
        """Transform request from HA to appropriate format for target device"""

        # Auto-detect input format if not provided
        if source_format is None:
            is_tcp_input = (
                len(request) >= 6 and int.from_bytes(request[2:4], "big") == 0
            )
            input_format = "TCP" if is_tcp_input else "RTU over TCP"
        else:
            input_format = source_format
            is_tcp_input = source_format == "TCP"

        # Determine target format based on device configuration
        if self.modbus_type == "rtu":
            target_format = "RTU Serial"
        elif self.modbus_type == "rtutcp":
            target_format = "RTU over TCP"
        else:
            target_format = "TCP"

        if self.modbus_type in ("rtutcp", "rtu"):
            # Target device expects RTU format

            if is_tcp_input:
                # Convert TCP format to RTU format
                # TCP: [MBAP Header 6 bytes][Unit ID][Function][Data]
                # RTU: [Unit ID][Function][Data][CRC 2 bytes]

                self.log.debug(
                    f"TRANSFORM: {input_format} → {target_format} (TCP → RTU conversion)"
                )

                if len(request) < 7:
                    self.log.error("Invalid TCP request length: %d bytes", len(request))
                    return request

                # Extract RTU data from TCP request (skip MBAP header)
                transaction_id = request[0:2]
                proto_id = request[2:4]
                uid = request[6]  # Unit ID from TCP message
                rtu_data = request[6:]  # Unit ID + Function + Data

                # Apply unit ID remapping
                new_uid = self.unit_id_remapping.setdefault(uid, uid)
                if uid != new_uid:
                    rtu_data = bytearray(rtu_data)
                    rtu_data[0] = new_uid
                    self.log.debug(
                        "remapping unit ID %s to %s in request", uid, new_uid
                    )

                # (rtcpmrtu handled in its own branch below)

                # Default RTU conversion: Calculate and append CRC
                crc_value = modbus_crc(rtu_data)
                rtu_request = bytes(rtu_data) + crc_value.to_bytes(2, byteorder="little")

                return rtu_request

            # Input is already RTU over TCP
            self.log.debug(
                f"TRANSFORM: {input_format} → {target_format} (RTU passthrough)"
            )

            uid = request[0]
            new_uid = self.unit_id_remapping.setdefault(uid, uid)
            if uid != new_uid:
                request = bytearray(request)
                request[0] = new_uid
                self.log.debug("remapping unit ID %s to %s in request", uid, new_uid)

            # (rtcpmrtu handled in its own branch below)

            # Default RTU passthrough
            # Recalculate CRC
            request = request[0:-2] + modbus_crc(request[0:-2]).to_bytes(2, byteorder="little")
            return request

        # Target device expects TCP format

        # Special handling for rtcpmrtu: build MBAP payload containing
        # routing bytes + RTU + CRC, and allow optional MBAP protocol override.
        if self.modbus_type == "rtcpmrtu":
            # rtcpmrtu treats device as TCP-hosted but payload contains a
            # routing bytes followed by an RTU frame and CRC. When HA sends TCP
            # input, convert to MBAP payload with routing+crc. When HA sends
            # RTU-over-TCP, wrap into MBAP similarly.
            if is_tcp_input:
                # Convert TCP input to rtcpmrtu MBAP payload
                if len(request) < 7:
                    self.log.error("Invalid TCP request length: %d bytes", len(request))
                    return request

                transaction_id = request[0:2]
                proto_id = request[2:4]
                uid = request[6]
                rtu_data = request[6:]

                # Apply unit ID remapping
                new_uid = self.unit_id_remapping.setdefault(uid, uid)
                if uid != new_uid:
                    rtu_data = bytearray(rtu_data)
                    rtu_data[0] = new_uid
                    rtu_data = bytes(rtu_data)

                crc_value = modbus_crc(rtu_data)
                routing = getattr(self, "routing_bytes", b"")
                payload = routing + bytes(rtu_data) + crc_value.to_bytes(2, byteorder="little")

                if getattr(self, "protocol_remapping", None) is not None:
                    proto_val = int(self.protocol_remapping)
                else:
                    proto_val = int.from_bytes(proto_id, "big")
                proto_bytes = proto_val.to_bytes(2, byteorder="big")
                length = len(payload).to_bytes(2, byteorder="big")
                tcp_request = transaction_id + proto_bytes + length + payload
                return tcp_request

            # Input is RTU over TCP - wrap into MBAP with prefix+CRC
            rtu_payload = bytes(request)
            crc_value = modbus_crc(rtu_payload)
            payload = getattr(self, "routing_bytes", b"") + rtu_payload + crc_value.to_bytes(2, byteorder="little")
            transaction_id = b"\x00\x01"
            proto_val = getattr(self, "protocol_remapping", None) or 0
            proto_bytes = int(proto_val).to_bytes(2, byteorder="big")
            length = len(payload).to_bytes(2, byteorder="big")
            return transaction_id + proto_bytes + length + payload

        if is_tcp_input:
            # Input is TCP, keep TCP format, only handle unit ID remapping
            self.log.debug(
                f"TRANSFORM: {input_format} → {target_format} (TCP passthrough)"
            )

            uid = request[6]
            new_uid = self.unit_id_remapping.setdefault(uid, uid)
            if uid != new_uid:
                request = bytearray(request)
                request[6] = new_uid
                self.log.debug("remapping unit ID %s to %s in request", uid, new_uid)
            return request

        # Convert RTU over TCP to TCP format
        # RTU: [Unit ID][Function][Data][CRC 2 bytes]
        # TCP: [MBAP Header 6 bytes][Unit ID][Function][Data]

        self.log.debug(
            f"TRANSFORM: {input_format} → {target_format} (RTU → TCP conversion)"
        )

        if len(request) < 4:
            self.log.error("Invalid RTU request length: %d bytes", len(request))
            return request

        # Extract RTU data (without CRC)
        rtu_data = request[:-2]  # Remove CRC
        uid = rtu_data[0]

        # Apply unit ID remapping
        new_uid = self.unit_id_remapping.setdefault(uid, uid)
        if uid != new_uid:
            rtu_data = bytearray(rtu_data)
            rtu_data[0] = new_uid
            self.log.debug("remapping unit ID %s to %s in request", uid, new_uid)

        # Create TCP request with MBAP header
        transaction_id = b"\x00\x01"  # Simple transaction ID
        protocol_id = b"\x00\x00"  # Modbus protocol
        length = len(rtu_data).to_bytes(2, byteorder="big")

        tcp_request = transaction_id + protocol_id + length + rtu_data

        return tcp_request

    def _transform_reply(
        self, reply, target_format="TCP"
    ):  # pylint: disable=too-many-branches,too-many-return-statements,too-many-statements
        """Transform device reply to format expected by HA"""

        # Determine source format based on device configuration
        if self.modbus_type == "rtu":
            source_format = "RTU Serial"
        elif self.modbus_type == "rtutcp":
            source_format = "RTU over TCP"
        else:
            source_format = "TCP"

        if self.modbus_type in ["rtutcp", "rtu"]:
            # Device sent RTU format

            if target_format == "TCP":
                # Convert RTU to TCP format for HA
                # RTU: [Unit ID][Function][Data][CRC 2 bytes]
                # TCP: [MBAP Header 6 bytes][Unit ID][Function][Data]

                self.log.debug(
                    f"TRANSFORM REPLY: {source_format} → {target_format} (RTU → TCP conversion)"
                )

                if len(reply) < 4:
                    self.log.error("Invalid RTU reply length: %d bytes", len(reply))
                    return reply

                # Extract RTU data (without CRC)
                rtu_data = reply[:-2]  # Remove CRC
                uid = rtu_data[0]

                # Apply inverse unit ID remapping
                inverse_unit_id_map = {v: k for k, v in self.unit_id_remapping.items()}
                new_uid = inverse_unit_id_map.setdefault(uid, uid)
                if uid != new_uid:
                    rtu_data = bytearray(rtu_data)
                    rtu_data[0] = new_uid
                    self.log.debug("remapping unit ID %s to %s in reply", uid, new_uid)

                # Create TCP reply with MBAP header
                # MBAP: [Transaction ID 2][Protocol ID 2][Length 2][Unit ID + Function + Data]
                transaction_id = b"\x00\x01"  # Simple transaction ID
                protocol_id = b"\x00\x00"  # Modbus protocol
                length = len(rtu_data).to_bytes(2, byteorder="big")

                tcp_reply = transaction_id + protocol_id + length + rtu_data

                return tcp_reply

        # Handle replies from rtcpmrtu devices that send a modified TCP payload
        if self.modbus_type == "rtcpmrtu":
            # Expect MBAP header + payload where payload = routing bytes + RTU + CRC
            if len(reply) >= 7:
                transaction_id = reply[0:2]
                # incoming proto may be override; HA expects 0
                payload = reply[6:]
                # strip routing bytes if present
                routing = getattr(self, "routing_bytes", b"")
                if routing and payload.startswith(routing):
                    payload_no_pre = payload[len(routing) :]
                else:
                    payload_no_pre = payload
                # strip CRC if present
                if len(payload_no_pre) >= 3:
                    rtu_no_crc = payload_no_pre[:-2]
                else:
                    rtu_no_crc = payload_no_pre

                # Apply inverse unit ID remapping
                if len(rtu_no_crc) > 0:
                    uid = rtu_no_crc[0]
                    inverse_unit_id_map = {v: k for k, v in self.unit_id_remapping.items()}
                    new_uid = inverse_unit_id_map.setdefault(uid, uid)
                    if uid != new_uid:
                        rtu_no_crc = bytearray(rtu_no_crc)
                        rtu_no_crc[0] = new_uid
                        rtu_no_crc = bytes(rtu_no_crc)

                # Build TCP reply expected by HA (protocol id 0)
                protocol_id = b"\x00\x00"
                length = len(rtu_no_crc).to_bytes(2, byteorder="big")
                tcp_reply = transaction_id + protocol_id + length + rtu_no_crc
                return tcp_reply

            # Keep RTU format for HA (RTU over TCP)
            self.log.debug(
                f"TRANSFORM REPLY: {source_format} → {target_format} (RTU passthrough)"
            )

            if len(reply) < 4:
                self.log.error("Invalid RTU reply length: %d bytes", len(reply))
                return reply

            # Apply inverse unit ID remapping
            uid = reply[0]
            inverse_unit_id_map = {v: k for k, v in self.unit_id_remapping.items()}
            new_uid = inverse_unit_id_map.setdefault(uid, uid)
            if uid != new_uid:
                reply = bytearray(reply)
                reply[0] = new_uid
                # Recalculate CRC
                reply = reply[0:-2] + modbus_crc(reply[0:-2]).to_bytes(
                    2, byteorder="little"
                )
                self.log.debug("remapping unit ID %s to %s in reply", uid, new_uid)

            return reply

        # Device sent TCP format

        if target_format == "TCP":
            # Keep TCP format for HA
            self.log.debug(
                f"TRANSFORM REPLY: {source_format} → {target_format} (TCP passthrough)"
            )

            uid = reply[6]
            inverse_unit_id_map = {v: k for k, v in self.unit_id_remapping.items()}
            new_uid = inverse_unit_id_map.setdefault(uid, uid)
            if uid != new_uid:
                reply = bytearray(reply)
                reply[6] = new_uid
                self.log.debug("remapping unit ID %s to %s in reply", uid, new_uid)
            return reply

        # Convert TCP to RTU over TCP format for HA
        # TCP: [MBAP Header 6 bytes][Unit ID][Function][Data]
        # RTU: [Unit ID][Function][Data][CRC 2 bytes]

        self.log.debug(
            f"TRANSFORM REPLY: {source_format} → {target_format} (TCP → RTU conversion)"
        )

        if len(reply) < 7:
            self.log.error("Invalid TCP reply length: %d bytes", len(reply))
            return reply

        # Extract RTU data from TCP reply (skip MBAP header)
        uid = reply[6]  # Unit ID from TCP message
        rtu_data = reply[6:]  # Unit ID + Function + Data

        # Apply inverse unit ID remapping
        inverse_unit_id_map = {v: k for k, v in self.unit_id_remapping.items()}
        new_uid = inverse_unit_id_map.setdefault(uid, uid)
        if uid != new_uid:
            rtu_data = bytearray(rtu_data)
            rtu_data[0] = new_uid
            self.log.debug("remapping unit ID %s to %s in reply", uid, new_uid)

        # Calculate and append CRC
        crc_value = modbus_crc(rtu_data)
        rtu_reply = bytes(rtu_data) + crc_value.to_bytes(2, byteorder="little")

        return rtu_reply

    async def handle_client(self, reader, writer):
        """Handle incoming client connection"""
        # Construct Client inside try/except so we can close the accepted
        # writer if Client construction fails to avoid leaking file descriptors.
        try:
            async with Client(reader, writer) as client:
                while True:
                    request = await client.read()
                    if not request:
                        break

                    # Detect client request format (TCP vs RTU over TCP)
                    is_tcp_request = (
                        len(request) >= 6 and int.from_bytes(request[2:4], "big") == 0
                    )
                    client_format = "TCP" if is_tcp_request else "RTU over TCP"

                    # Log proxy activity overview
                    if hasattr(self, "modbus_type") and self.modbus_type == "rtu":
                        self.log.debug(
                            f"PROXY: {client.client_ip}:{client.client_port} → "
                            f"RTU:{self.device} (Request #{client.request_count}, {client_format})"
                        )
                    elif hasattr(self, "modbus_type") and self.modbus_type == "rtutcp":
                        self.log.debug(
                            f"PROXY: {client.client_ip}:{client.client_port} → "
                            f"RTU(over)TCP:{self.modbus_host}:{self.modbus_port}"
                            f" (Request #{client.request_count}, {client_format})"
                        )
                    elif hasattr(self, "modbus_type") and self.modbus_type == "rtcpmrtu":
                        self.log.debug(
                            f"PROXY: {client.client_ip}:{client.client_port} → "
                            f"UDP:{self.modbus_host_udp}:{self.modbus_port_udp}"
                            f" TCP:{self.modbus_host}:{self.modbus_port}"
                            f" (Request #{client.request_count}, {client_format})"
                        )
                    else:
                        self.log.debug(
                            f"PROXY: {client.client_ip}:{client.client_port} → "
                            f"TCP:{self.modbus_host}:{self.modbus_port}"
                            f" (Request #{client.request_count}, {client_format})"
                        )

                    reply = await self.write_read(
                        self._transform_request(request, client_format)
                    )
                    if not reply:
                        break
                    result = await client.write(self._transform_reply(reply, client_format))
                    if not result:
                        break
        except Exception as err:
            # Ensure the accepted socket is closed on any construction or handling error
            try:
                if writer is not None:
                    # Try to close underlying socket first (defensive), then the writer
                    try:
                        sock = writer.get_extra_info("socket")
                        if sock is not None:
                            try:
                                sock.close()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                self.log.error("client handler error: %r", err)
            except Exception:
                pass

    async def start(self):
        """Start the ModBus proxy server"""
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port, start_serving=True
        )

    async def stop(self):
        """Stop the ModBus proxy server"""
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        await self.close()

    async def serve_forever(self):
        """Serve forever until cancelled"""
        if self.server is None:
            await self.start()
        async with self.server:
            device_info = (
                f"Device({self.modbus_host}:{self.modbus_port})"
                if self.modbus_type in ["tcp", "rtutcp", "rtcpmrtu"]
                else f"Device({self.device})"
            )
            self.log.info(
                f"Ready to accept requests on {self.host}:{self.port} for {device_info}"
            )
            await self.server.serve_forever()


def load_config(file_name):
    """Load configuration from file (TOML, YAML, JSON)"""
    file_name = pathlib.Path(file_name)
    ext = file_name.suffix
    if ext.endswith("toml"):
        from toml import load  # pylint: disable=import-outside-toplevel
    elif ext.endswith("yml") or ext.endswith("yaml"):
        import yaml  # pylint: disable=import-outside-toplevel

        def load(fobj):
            return yaml.load(fobj, Loader=yaml.Loader)

    elif ext.endswith("json"):
        from json import load  # pylint: disable=import-outside-toplevel
    else:
        raise NotImplementedError
    with open(file_name, encoding="utf-8") as fobj:
        return load(fobj)


def prepare_log(config):
    """Prepare logging according to config or default settings"""
    cfg = config.get("logging")
    if not cfg:
        cfg = DEFAULT_LOG_CONFIG
    if cfg:
        cfg.setdefault("version", 1)
        cfg.setdefault("disable_existing_loggers", False)
        logging.config.dictConfig(cfg)

        # Note: Using standard Python logging levels (DEBUG, INFO, WARNING, ERROR)

    warnings.simplefilter("always", DeprecationWarning)
    logging.captureWarnings(True)
    return log


def parse_args(args=None):
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="ModBus proxy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config-file", default=None, type=str, help="config file"
    )
    parser.add_argument("-b", "--bind", default=None, type=str, help="listen address")
    parser.add_argument(
        "--modbus",
        default=None,
        type=str,
        help="modbus device address (ex: tcp://plc.acme.org:502)",
    )
    parser.add_argument(
        "--modbus-connection-time",
        type=float,
        default=0,
        help="delay after establishing connection with modbus before first request",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="modbus connection and request timeout in seconds",
    )
    options = parser.parse_args(args=args)

    if not options.config_file and not options.modbus:
        parser.exit(1, "must give a config-file or/and a --modbus")
    return options


def create_config(args):
    """Create configuration dictionary from args and config file"""
    if args.config_file is None:
        assert args.modbus
    config = load_config(args.config_file) if args.config_file else {}
    prepare_log(config)
    log.info("Starting...")
    devices = config.setdefault("devices", [])
    if args.modbus:
        listen = {"bind": ":502" if args.bind is None else args.bind}
        devices.append(
            {
                "modbus": {
                    "url": args.modbus,
                    "timeout": args.timeout,
                    "connection_time": args.modbus_connection_time,
                },
                "listen": listen,
            }
        )
    return config


def create_bridges(config):
    """Create ModBus bridges from configuration"""
    return [ModBus(cfg) for cfg in config["devices"]]


async def start_bridges(bridges):
    """Start all bridges"""
    coros = [bridge.start() for bridge in bridges]
    await asyncio.gather(*coros)


async def run_bridges(bridges, ready=None):
    """Run all bridges until cancelled"""
    async with contextlib.AsyncExitStack() as stack:
        coros = [stack.enter_async_context(bridge) for bridge in bridges]
        await asyncio.gather(*coros)
        await start_bridges(bridges)
        if ready is not None:
            ready.set(bridges)
        coros = [bridge.serve_forever() for bridge in bridges]
        await asyncio.gather(*coros)


async def run(args=None, ready=None):
    """Run the modbus proxy with given arguments and optional ready event."""
    args = parse_args(args)
    config = create_config(args)
    bridges = create_bridges(config)
    await run_bridges(bridges, ready=ready)


def main():
    """Main entry point for modbus proxy"""
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.warning("Ctrl-C pressed. Bailing out!")


if __name__ == "__main__":
    main()
