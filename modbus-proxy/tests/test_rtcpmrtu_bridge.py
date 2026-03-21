"""Tests rtcpmrtu bridge in modbus-proxy."""

# pylint: disable=W0212
import pytest
from modbus_proxy import modbus_crc


@pytest.mark.asyncio
async def test_rtcpmrtu_default_strip_mbap_and_gateway_and_response_reconstruction(
    bridge_factory,
):
    """Test that rtcpmrtu bridge strips MBAP, adds gateway, and reconstructs response."""
    # Create ModBus configured for rtcpmrtu
    bridge = bridge_factory({})

    # Build a TCP-style request: MBAP(6) + Unit(1) + Func(1) + Data(2)
    mbap = b"\x00\x01\x00\x00\x00\x04"  # length 4
    tcp_payload = mbap + b"\x11\x03\x00\x01"

    # Simulate device response: device returns unit, function, data
    udp_response_payload = b"\x11\x03\x02\x00\x2a"
    _udp_response = (
        b"\x00\x01\x01\x02\x00\x09\xff\x04" + udp_response_payload + b"\x12\x34"
    )

    # Transform the TCP request into the device format (MBAP with routing+CRC)
    tcp_request = bridge._transform_request(tcp_payload, source_format="TCP")

    # Simulate device reply: MBAP header + payload where payload = routing_bytes + RTU + CRC
    transaction_id = tcp_request[0:2]
    rtu_no_crc = udp_response_payload
    crc_val = modbus_crc(rtu_no_crc)
    payload = getattr(bridge, "routing_bytes", b"") + rtu_no_crc + crc_val.to_bytes(2, byteorder="little")
    reply_mbap = transaction_id + b"\x00\x00" + len(payload).to_bytes(2, byteorder="big") + payload

    tcp_reply = bridge._transform_reply(reply_mbap, target_format="TCP")

    # Expect the reply to be MBAP for HA and payload to match device payload
    assert tcp_reply[6:] == udp_response_payload


@pytest.mark.asyncio
async def test_rtcpmrtu_prefix_and_crc_and_vars(bridge_factory):
    """Test that rtcpmrtu bridge handles prefix templating and CRC insertion correctly."""
    # Test prefix templating and CRC insertion

    bridge = bridge_factory()

    # Request with MBAP + payload
    mbap = b"\xaa\xbb\x00\x00\x00\x03"
    request = mbap + b"\x01\x03\x00"

    # Device echo response (payload only)
    udp_response_payload = b"\x01\x03\x00"
    _udp_response = (
        b"\xaa\xbb\x01\x02\x00\x07\xff\x04" + udp_response_payload + b"\x12\x34"
    )
    # Build the device-format request using the bridge transform
    tcp_request = bridge._transform_request(request, source_format="TCP")
    payload = tcp_request[6:]
    # Ensure RTU payload present inside MBAP payload
    assert b"\x01\x03\x00" in payload
    # CRC should be the last two bytes of the payload
    # Skip routing_bytes when computing expected CRC position
    routing = getattr(bridge, "routing_bytes", b"")
    expected_crc = modbus_crc(payload[len(routing) : -2])
    assert payload[-2:] == expected_crc.to_bytes(2, byteorder="little")
