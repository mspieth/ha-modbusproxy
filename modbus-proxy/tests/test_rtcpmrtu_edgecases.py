"""RTC-PM-RTU edge case tests."""

# pylint: disable=protected-access
import struct
import pytest

from modbus_proxy import modbus_crc


@pytest.mark.asyncio
async def test_rtcpmrtu_malformed_prefix_template(bridge_factory):
    """Test that unknown token in prefix template is ignored and does not crash."""
    bridge = bridge_factory()
    payload = b"\x01\x03\x02\x00\x2a"
    plen = len(payload)
    _udp_pkt = struct.pack(
        f">HHHB{plen}sH",
        0x0002,
        0x0102,
        plen + 3,
        0xFF,
        payload,
        modbus_crc(payload),
    )
    # Transform the request and simulate a device reply; ensure no crash
    mbap = b"\x00\x02\x00\x00\x00\x03"
    req = mbap + b"\x01\x03\x00"
    tcp_req = bridge._transform_request(req, source_format="TCP")
    # Build reply payload from RTU payload + CRC
    rtu_no_crc = payload
    crc_val = modbus_crc(rtu_no_crc)
    payload_mb = getattr(bridge, "routing_bytes", b"") + rtu_no_crc + crc_val.to_bytes(2, byteorder="little")
    reply_mbap = tcp_req[0:2] + b"\x00\x00" + len(payload_mb).to_bytes(2, byteorder="big") + payload_mb
    res = bridge._transform_reply(reply_mbap, target_format="TCP")
    assert res is not None


@pytest.mark.asyncio
async def test_rtcpmrtu_gateway_insertion_edge(bridge_factory):
    """Test that gateway ID insertion handles short payloads safely."""
    bridge = bridge_factory({})
    payload = b"\x01\x03\x02\x00\x2a"
    plen = len(payload)
    _udp_pkt = struct.pack(
        f">HHHB{plen}sH",
        0x0004,
        0x0102,
        plen + 3,
        0xFF,
        payload,
        modbus_crc(payload),
    )
    bridge.rtcpmrtu_protocol.queue.put_nowait(
        (_udp_pkt, (bridge.modbus_host, bridge.modbus_port))
    )

    mbap = b"\x00\x04\x00\x00\x00\x00"
    req = mbap  # no payload after MBAP
    tcp_req = bridge._transform_request(req, source_format="TCP")
    rtu_no_crc = payload
    crc_val = modbus_crc(rtu_no_crc)
    payload_mb = getattr(bridge, "routing_bytes", b"") + rtu_no_crc + crc_val.to_bytes(2, byteorder="little")
    reply_mbap = tcp_req[0:2] + b"\x00\x00" + len(payload_mb).to_bytes(2, byteorder="big") + payload_mb
    res = bridge._transform_reply(reply_mbap, target_format="TCP")
    assert res is not None
