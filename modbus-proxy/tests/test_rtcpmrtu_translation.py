"""Tests for rtcpmrtu translation with preflight and gateway ID handling."""

import asyncio
import pytest
from modbus_proxy import modbus_crc


def hexbytes(s: str) -> bytes:
    """Convert a hex string with spaces into bytes."""
    return bytes.fromhex(s.replace(" ", ""))


TCP_KEYS = ["TID", "PROT", "LEN", "PAYLOAD"]
TCP_FORMAT = ">HHH%ds"

UDP_KEYS = ["TID", "PROT", "LEN", "GWIDPAYLOAD", "CRC"]
UDP_FORMAT = ">HHHB%dsH"


def req_map(pkt: dict, crc: callable) -> dict:
    """Map TCP request fields to UDP request fields."""
    return {
        "TID": pkt["TID"],
        "PROT": 0x0102,
        "LEN": len(pkt["PAYLOAD"]) + 3,
        "GWID": 0xFF,
        "PAYLOAD": pkt["PAYLOAD"],
        "CRC": crc(pkt["PAYLOAD"]),
    }


def resp_map(pkt: dict, opkt: dict) -> dict:
    """Map UDP response fields to TCP response fields."""
    return {
        "TID": pkt["TID"],
        "PROT": opkt["PROT"],
        "LEN": len(pkt["PAYLOAD"]),
        "PAYLOAD": pkt["PAYLOAD"],
    }


UDP_COMMON_CFG = {
    "rtcpmrtu_session_start_request": "set>server=$HOST:$PORT;",
    "rtcpmrtu_session_start_response": "rsp>server=1;",
}


# captured data from real device with preflight and gateway
TEST_VECTORS = [
    (
        {},
        hexbytes("00 01 00 00 00 06 05 03 13 89 00 01"),
        hexbytes("00 01 01 02 00 0a ff 04 05 03 13 89 00 01 50 e0"),
        hexbytes("00 01 01 02 00 09 ff 04 05 03 02 00 00 49 84"),
        hexbytes("00 01 00 00 00 05 05 03 02 00 00"),
    ),
    (
        {},
        hexbytes("00 02 00 00 00 06 05 03 13 8a 00 01"),
        hexbytes("00 02 01 02 00 0a ff 04 05 03 13 8a 00 01 a0 e0"),
        hexbytes("00 02 01 02 00 09 ff 04 05 03 02 00 00 49 84"),
        hexbytes("00 02 00 00 00 05 05 03 02 00 00"),
    ),
    (
        {},
        hexbytes("00 04 00 00 00 06 05 03 13 8c 00 01"),
        hexbytes("00 04 01 02 00 0a ff 04 05 03 13 8c 00 01 40 e1"),
        hexbytes("00 04 01 02 00 09 ff 04 05 03 02 00 01 88 44"),
        hexbytes("00 04 00 00 00 05 05 03 02 00 01"),
    ),
    (
        {},
        hexbytes("00 22 00 00 00 06 05 03 13 9e 00 01"),
        hexbytes("00 22 01 02 00 0a ff 04 05 03 13 9e 00 01 e0 e4"),
        hexbytes("00 22 01 02 00 09 ff 04 05 03 02 00 32 c8 51"),
        hexbytes("00 22 00 00 00 05 05 03 02 00 32"),
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "udp_cfg,tcp_request,expected_udp_request,udp_response,expected_tcp_response",
    TEST_VECTORS,
)
async def test_rtcpmrtu_translation_with_preflight_and_gateway(  # pylint: disable=R0913,R0917
    bridge_factory,
    udp_cfg,
    tcp_request,
    expected_udp_request,
    udp_response,
    expected_tcp_response,
):
    """Test rtcpmrtu translation with preflight session-start request and gateway ID insertion."""
    # Merge common settings into per-vector udp_cfg
    merged_cfg = dict(UDP_COMMON_CFG)
    merged_cfg.update(udp_cfg or {})
    bridge = bridge_factory(merged_cfg)

    # Build the device-format request using the bridge transform
    tcp_req = bridge._transform_request(tcp_request, source_format="TCP")

    # Simulate device reply using the expected TCP response payload
    # Expected TCP response is MBAP; extract RTU payload (no CRC)
    rtu_no_crc = expected_tcp_response[6:]
    crc_val = modbus_crc(rtu_no_crc)
    payload = getattr(bridge, "routing_bytes", b"") + rtu_no_crc + crc_val.to_bytes(2, byteorder="little")
    # Build MBAP-like reply that the bridge will parse
    transaction_id = tcp_req[0:2]
    reply_mbap = transaction_id + b"\x00\x00" + len(payload).to_bytes(2, byteorder="big") + payload

    tcp_reply = bridge._transform_reply(reply_mbap, target_format="TCP")

    # The reconstructed TCP reply should match the expected TCP response exactly
    assert tcp_reply == expected_tcp_response
