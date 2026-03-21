"""Tests for rtcpmrtu translation with preflight and gateway ID handling."""

# pylint: disable=protected-access
import pytest


def hexbytes(s: str) -> bytes:
    """Convert a hex string with spaces into bytes."""
    return bytes.fromhex(s.replace(" ", ""))


COMMON_CFG = {
    "rtcpmrtu_session_start_request": "set>server=$HOST:$PORT;",
    "rtcpmrtu_session_start_response": "rsp>server=1;",
    "protocol_remapping": "0102",
    "routing_bytes": "FF04",
}


# captured data from real device with routing and gateway
TEST_VECTORS = [
    pytest.param(
        {},
        hexbytes("00 01 00 00 00 06 05 03 13 89 00 01"),
        hexbytes("00 01 01 02 00 0a ff 04 05 03 13 89 00 01 50 e0"),
        hexbytes("00 01 01 02 00 09 ff 04 05 03 02 00 00 49 84"),
        hexbytes("00 01 00 00 00 05 05 03 02 00 00"),
        id="1",
    ),
    pytest.param(
        {},
        hexbytes("00 02 00 00 00 06 05 03 13 8a 00 01"),
        hexbytes("00 02 01 02 00 0a ff 04 05 03 13 8a 00 01 a0 e0"),
        hexbytes("00 02 01 02 00 09 ff 04 05 03 02 00 00 49 84"),
        hexbytes("00 02 00 00 00 05 05 03 02 00 00"),
        id="2",
    ),
    pytest.param(
        {},
        hexbytes("00 04 00 00 00 06 05 03 13 8c 00 01"),
        hexbytes("00 04 01 02 00 0a ff 04 05 03 13 8c 00 01 40 e1"),
        hexbytes("00 04 01 02 00 09 ff 04 05 03 02 00 01 88 44"),
        hexbytes("00 04 00 00 00 05 05 03 02 00 01"),
        id="3",
    ),
    pytest.param(
        {},
        hexbytes("00 22 00 00 00 06 05 03 13 9e 00 01"),
        hexbytes("00 22 01 02 00 0a ff 04 05 03 13 9e 00 01 e0 e4"),
        hexbytes("00 22 01 02 00 09 ff 04 05 03 02 00 32 c8 51"),
        hexbytes("00 22 00 00 00 05 05 03 02 00 32"),
        id="4",
    ),
]


@pytest.mark.parametrize(
    "downstream_cfg,tcp_request,expected_downstream_request,downstream_response,expected_tcp_response",
    TEST_VECTORS,
)
async def test_rtcpmrtu_translation_with_routing_and_gateway(  # pylint: disable=R0913,R0917
    bridge_factory,
    downstream_cfg,
    tcp_request,
    expected_downstream_request,
    downstream_response,
    expected_tcp_response,
):
    """Test rtcpmrtu translation with routing session-start request and gateway ID insertion."""
    # Merge common settings into per-vector cfg
    merged_cfg = dict(COMMON_CFG)
    merged_cfg.update(downstream_cfg or {})
    bridge = bridge_factory(merged_cfg)

    # Build the device-format request using the bridge transform
    downstream_request = bridge._transform_request(tcp_request, source_format="TCP")
    print(f"TCP request                : {tcp_request.hex()}")
    print(f"Downstream request         : {downstream_request.hex()}")
    print(f"Expected downstream request: {expected_downstream_request.hex()}")
    assert downstream_request == expected_downstream_request

    # Simulate device reply using the expected TCP response payload
    tcp_reply = bridge._transform_reply(downstream_response, target_format="TCP")
    print(f"Downstream response        : {downstream_response.hex()}")
    print(f"TCP reply                  : {tcp_reply.hex()}")
    print(f"Expected TCP reply         : {expected_tcp_response.hex()}")

    assert tcp_reply == expected_tcp_response
