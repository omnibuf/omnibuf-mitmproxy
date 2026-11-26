"""Tests for omnibuf_mitmproxy wire decoding, envelope framing, schema overlay, and rendering."""

from __future__ import annotations

import gzip
import json
import struct
from pathlib import Path

import pytest

import omnibuf_mitmproxy as om

CORPUS_PATH = Path(__file__).resolve().parents[2] / "omnibuf-go" / "testdata" / "conformance_corpus.json"


def _sample_message_bytes() -> bytes:
    # field #1 WireString = "fra-core-01"
    # field #2 WireUint   = 1 (enum ESTABLISHED)
    # field #3 WireSint   = -2 (zigzag -> 3 -> varint (3<<1)|1 = 0x07)
    # field #4 WireBoolTrue
    out = bytearray()
    # #1 string "fra-core-01" (len 11 -> (11<<1)|1 = 0x17)
    # tag (1<<4)|10 = 26 -> (26<<1)|1 = 0x35
    out.extend(b"\x35\x17fra-core-01")
    # #2 uint 1: tag (2<<4)|0 = 32 -> (32<<1)|1 = 0x41; val 1 -> 0x03
    out.extend(b"\x41\x03")
    # #3 sint -2: tag (3<<4)|1 = 49 -> (49<<1)|1 = 0x63; zigzag(-2)=3 -> 0x07
    out.extend(b"\x63\x07")
    # #4 bool true: tag (4<<4)|3 = 67 -> (67<<1)|1 = 0x87
    out.extend(b"\x87")
    return bytes(out)


def test_decode_and_format_unary() -> None:
    raw = _sample_message_bytes()
    title, lines = om.format_payload(raw, content_type="application/omnibuf")
    assert title == "OmniBuf (4 fields)"
    text = om.lines_to_text(lines)
    assert '#1 (string): "fra-core-01"' in text
    assert "#2 (uint): 1" in text
    assert "#3 (sint): -2" in text
    assert "#4 (bool): true" in text


def test_schema_overlay_lightweight_and_fds() -> None:
    raw = _sample_message_bytes()
    light_schema = om.load_schema_json(
        json.dumps(
            {
                "root": "demo.v1.PeerUpdate",
                "messages": {
                    "demo.v1.PeerUpdate": {
                        "fields": {
                            "1": {"name": "router"},
                            "2": {"name": "state", "enum": "demo.v1.PeerState"},
                            "3": "delta",
                            "4": "established",
                        }
                    }
                },
                "enums": {"demo.v1.PeerState": {"1": "PEER_STATE_ESTABLISHED"}},
            }
        )
    )
    _, lines = om.format_payload(raw, content_type="application/omnibuf", schema=light_schema)
    text = om.lines_to_text(lines)
    assert "# demo.v1.PeerUpdate" in text
    assert '#1 router (string): "fra-core-01"' in text
    assert "#2 state (uint): PEER_STATE_ESTABLISHED (1)" in text
    assert "#3 delta (sint): -2" in text
    assert "#4 established (bool): true" in text

    fds_schema = om.load_schema_json(
        json.dumps(
            {
                "file": [
                    {
                        "package": "demo.v1",
                        "enumType": [
                            {
                                "name": "PeerState",
                                "value": [{"name": "PEER_STATE_ESTABLISHED", "number": 1}],
                            }
                        ],
                        "messageType": [
                            {
                                "name": "PeerUpdate",
                                "field": [
                                    {"name": "router", "number": 1, "type": "TYPE_STRING"},
                                    {
                                        "name": "state",
                                        "number": 2,
                                        "type": "TYPE_ENUM",
                                        "typeName": ".demo.v1.PeerState",
                                    },
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    _, lines2 = om.format_payload(raw, content_type="application/omnibuf", schema=fds_schema)
    text2 = om.lines_to_text(lines2)
    assert "#2 state (uint): PEER_STATE_ESTABLISHED (1)" in text2


def test_connect_streaming_envelope_with_gzip_and_end_stream() -> None:
    msg = _sample_message_bytes()
    gz_msg = gzip.compress(msg)
    end_json = b"{}"
    stream = (
        struct.pack(">BI", 0x00, len(msg))
        + msg
        + struct.pack(">BI", 0x01, len(gz_msg))
        + gz_msg
        + struct.pack(">BI", 0x02, len(end_json))
        + end_json
    )
    title, lines = om.format_payload(stream, content_type="application/connect+omnibuf")
    assert title == "OmniBuf Stream (3 frames)"
    text = om.lines_to_text(lines)
    assert "Frame #1" in text
    assert "Frame #2" in text and "compressed" in text
    assert "Frame #3" in text and "end-stream" in text
    assert "{}" in text


@pytest.mark.skipif(not CORPUS_PATH.exists(), reason="conformance_corpus.json not present")
def test_conformance_corpus() -> None:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    for vec in corpus["valid_vectors"]:
        if vec.get("skip_blind"):
            continue
        raw = bytes.fromhex(vec["wire_hex"])
        msg = om.decode_message(raw)
        assert isinstance(msg, om.DecodedMessage), vec["name"]

    for vec in corpus["invalid_cases"]:
        raw = bytes.fromhex(vec["wire_hex"])
        with pytest.raises(om.OmniBufDecodeError, match=".+"):
            om.decode_message(raw)
