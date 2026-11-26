"""mitmproxy ContentView addon for OmniBuf, Connect+OmniBuf, and gRPC+OmniBuf traffic.

Single-script usage:
    mitmproxy -s omnibuf_mitmproxy.py
    mitmproxy -s omnibuf_mitmproxy.py --set omnibuf_schema=/path/to/schema.json
    mitmweb   -s omnibuf_mitmproxy.py --set omnibuf_schema=/path/to/schema.json

Supports:
  * application/omnibuf, application/x-omnibuf
  * application/connect+omnibuf, application/connect+x-omnibuf (5-byte streaming envelopes)
  * application/grpc+omnibuf, application/grpc+x-omnibuf (5-byte streaming envelopes)
  * Inline Field #0 (SchemaMeta) field names
  * Optional external JSON schema overlay (OmniBuf lightweight JSON or Protobuf FileDescriptorSet JSON)
"""

from __future__ import annotations

import contextlib
import gzip
import json
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

# ---------------------------------------------------------------------------
# OmniBuf v1 DRAFT-1 wire constants & pure-Python schemaless decoder
# ---------------------------------------------------------------------------

WIRE_UINT = 0
WIRE_SINT = 1
WIRE_BOOL_FALSE = 2
WIRE_BOOL_TRUE = 3
WIRE_FIXED32 = 4
WIRE_FIXED64 = 5
WIRE_SFIXED32 = 6
WIRE_SFIXED64 = 7
WIRE_FLOAT32 = 8
WIRE_FLOAT64 = 9
WIRE_STRING = 10
WIRE_BYTES = 11
WIRE_SUB_MSG = 12
WIRE_ARRAY = 13
WIRE_MAP = 14
WIRE_EXTENDED = 15

WIRE_TYPE_NAMES: dict[int, str] = {
    0: "uint",
    1: "sint",
    2: "bool",
    3: "bool",
    4: "fixed32",
    5: "fixed64",
    6: "sfixed32",
    7: "sfixed64",
    8: "float32",
    9: "float64",
    10: "string",
    11: "bytes",
    12: "submsg",
    13: "array",
    14: "map",
    15: "extended",
}

MAX_CONTAINER_DEPTH = 32
MAX_FIELD_NUMBER = 536_870_911

VALID_MAP_KEY_TYPES: frozenset[int] = frozenset(
    {
        WIRE_UINT,
        WIRE_SINT,
        WIRE_BOOL_FALSE,
        WIRE_FIXED32,
        WIRE_FIXED64,
        WIRE_SFIXED32,
        WIRE_SFIXED64,
        WIRE_STRING,
    }
)

OMNIBUF_MEDIA_TYPES: tuple[str, ...] = (
    "application/omnibuf",
    "application/x-omnibuf",
    "application/connect+omnibuf",
    "application/connect+x-omnibuf",
    "application/grpc+omnibuf",
    "application/grpc+x-omnibuf",
    "application/grpc-web+omnibuf",
    "application/grpc-web+x-omnibuf",
)

ENVELOPE_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        "application/connect+omnibuf",
        "application/connect+x-omnibuf",
        "application/grpc+omnibuf",
        "application/grpc+x-omnibuf",
        "application/grpc-web+omnibuf",
        "application/grpc-web+x-omnibuf",
    }
)

_U16_LE = struct.Struct("<H")
_U32_LE = struct.Struct("<I")
_I32_LE = struct.Struct("<i")
_U64_LE = struct.Struct("<Q")
_I64_LE = struct.Struct("<q")
_F32_LE = struct.Struct("<f")
_F64_LE = struct.Struct("<d")
_ENV_HDR = struct.Struct(">BI")


class OmniBufDecodeError(ValueError):
    """Raised when an OmniBuf wire payload is truncated or malformed."""


@dataclass(slots=True)
class SchemaMeta:
    type_name: str = ""
    fields: dict[int, str] = field(default_factory=dict)
    children: dict[int, SchemaMeta] = field(default_factory=dict)


@dataclass(slots=True)
class DecodedField:
    field_num: int
    wire_type: int
    start_pos: int
    end_pos: int
    value: Any


@dataclass(slots=True)
class DecodedMessage:
    fields: list[DecodedField]
    schema_meta: SchemaMeta | None = None


@dataclass(slots=True)
class DecodedArray:
    elem_wire_type: int
    count: int
    items: list[Any]


@dataclass(slots=True)
class DecodedMap:
    key_wire_type: int
    val_wire_type: int
    count: int
    entries: list[tuple[Any, Any]]


@dataclass(slots=True)
class DecodedExtended:
    subtype: int
    payload: bytes


@dataclass(slots=True)
class EnvelopeFrame:
    flags: int
    length: int
    payload: bytes

    @property
    def compressed(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def end_stream(self) -> bool:
        return bool(self.flags & 0x02)


@dataclass(slots=True)
class FieldSchema:
    name: str | None = None
    message: str | None = None
    enum: str | None = None


@dataclass(slots=True)
class SchemaOverlay:
    root: str | None = None
    messages: dict[str, dict[int, FieldSchema]] = field(default_factory=dict)
    enums: dict[str, dict[int, str]] = field(default_factory=dict)


def _decode_varint(buf: memoryview, pos: int, end: int) -> tuple[int, int]:
    if pos >= end:
        raise OmniBufDecodeError(f"truncated varint at byte {pos}")
    b0 = buf[pos]
    if b0 & 1:
        return b0 >> 1, pos + 1
    if b0 & 2:
        if pos + 2 > end:
            raise OmniBufDecodeError(f"truncated 2-byte varint at byte {pos}")
        return _U16_LE.unpack_from(buf, pos)[0] >> 2, pos + 2
    if b0 & 4:
        if pos + 4 > end:
            raise OmniBufDecodeError(f"truncated 4-byte varint at byte {pos}")
        return _U32_LE.unpack_from(buf, pos)[0] >> 3, pos + 4
    if b0 == 0:
        if pos + 9 > end:
            raise OmniBufDecodeError(f"truncated 9-byte varint at byte {pos}")
        return _U64_LE.unpack_from(buf, pos + 1)[0], pos + 9
    raise OmniBufDecodeError(f"reserved varint marker 0x{b0:02x} at byte {pos}")


def _decode_tag(buf: memoryview, pos: int, end: int) -> tuple[int, int, int]:
    tag, next_pos = _decode_varint(buf, pos, end)
    fnum = tag >> 4
    wt = tag & 0x0F
    if fnum > MAX_FIELD_NUMBER:
        raise OmniBufDecodeError(f"field number {fnum} out of range at byte {pos}")
    if fnum == 0 and wt != WIRE_SUB_MSG:
        raise OmniBufDecodeError(f"Field #0 requires WireSubMsg, got {wt} at byte {pos}")
    return fnum, wt, next_pos


def _read_len_slice(buf: memoryview, pos: int, end: int, min_len: int = 0) -> tuple[memoryview, int]:
    length, payload_start = _decode_varint(buf, pos, end)
    if length < min_len or length > end - payload_start:
        raise OmniBufDecodeError(f"invalid length {length} at byte {pos}")
    return buf[payload_start : payload_start + length], payload_start + length


def _decode_zigzag(u: int) -> int:
    return (u >> 1) ^ -(u & 1)


def _decode_utf8(raw: memoryview, pos: int) -> str:
    try:
        return bytes(raw).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise OmniBufDecodeError(f"invalid UTF-8 at byte {pos}: {exc}") from exc


def _merge_schema_meta(base: SchemaMeta | None, overlay: SchemaMeta | None) -> SchemaMeta | None:
    if overlay is None:
        return base
    out = SchemaMeta(
        type_name=base.type_name if base else "",
        fields=dict(base.fields) if base else {},
        children=dict(base.children) if base else {},
    )
    if overlay.type_name:
        out.type_name = overlay.type_name
    out.fields.update(overlay.fields)
    for k, child in overlay.children.items():
        merged = _merge_schema_meta(out.children.get(k), child)
        if merged is not None:
            out.children[k] = merged
    return out


def _decode_schema_meta(buf: memoryview, depth: int = 1, max_depth: int = MAX_CONTAINER_DEPTH) -> SchemaMeta:
    if depth > max_depth:
        raise OmniBufDecodeError(f"SchemaMeta depth {depth} exceeds {max_depth}")
    n = len(buf)
    pos = 0
    meta = SchemaMeta()
    while pos < n:
        fnum, wt, pos = _decode_tag(buf, pos, n)
        if fnum == 0:
            raise OmniBufDecodeError("nested Field #0 inside SchemaMeta")
        if fnum == 1:
            if wt != WIRE_STRING:
                raise OmniBufDecodeError(f"SchemaMeta field #1 must be WireString, got {wt}")
            raw, pos = _read_len_slice(buf, pos, n, 0)
            meta.type_name = _decode_utf8(raw, pos)
        elif fnum == 2:
            if wt != WIRE_MAP:
                raise OmniBufDecodeError(f"SchemaMeta field #2 must be WireMap, got {wt}")
            if depth + 1 > max_depth:
                raise OmniBufDecodeError("SchemaMeta fields map exceeds max depth")
            body, pos = _read_len_slice(buf, pos, n, 3)
            if body[0] != WIRE_UINT or body[1] != WIRE_STRING:
                raise OmniBufDecodeError("invalid SchemaMeta fields map types")
            count, p = _decode_varint(body, 2, len(body))
            rem = len(body) - p
            if (count == 0 and rem != 0) or (count > 0 and count > (rem >> 1)):
                raise OmniBufDecodeError("invalid SchemaMeta fields map count")
            for _ in range(count):
                k, p = _decode_varint(body, p, len(body))
                if k == 0 or k > MAX_FIELD_NUMBER:
                    raise OmniBufDecodeError(f"invalid SchemaMeta field number {k}")
                v_raw, p = _read_len_slice(body, p, len(body), 0)
                meta.fields[k] = _decode_utf8(v_raw, p)
            if p != len(body):
                raise OmniBufDecodeError("trailing bytes in SchemaMeta fields map")
        elif fnum == 3:
            if wt != WIRE_MAP:
                raise OmniBufDecodeError(f"SchemaMeta field #3 must be WireMap, got {wt}")
            if depth + 1 > max_depth:
                raise OmniBufDecodeError("SchemaMeta children map exceeds max depth")
            body, pos = _read_len_slice(buf, pos, n, 3)
            if body[0] != WIRE_UINT or body[1] != WIRE_SUB_MSG:
                raise OmniBufDecodeError("invalid SchemaMeta children map types")
            count, p = _decode_varint(body, 2, len(body))
            rem = len(body) - p
            if (count == 0 and rem != 0) or (count > 0 and count > (rem >> 1)):
                raise OmniBufDecodeError("invalid SchemaMeta children map count")
            local_children: dict[int, SchemaMeta] = {}
            for _ in range(count):
                k, p = _decode_varint(body, p, len(body))
                if k == 0 or k > MAX_FIELD_NUMBER:
                    raise OmniBufDecodeError(f"invalid SchemaMeta child field number {k}")
                child_raw, p = _read_len_slice(body, p, len(body), 0)
                local_children[k] = _decode_schema_meta(child_raw, depth + 2, max_depth)
            if p != len(body):
                raise OmniBufDecodeError("trailing bytes in SchemaMeta children map")
            for k, child_meta in local_children.items():
                merged = _merge_schema_meta(meta.children.get(k), child_meta)
                if merged is not None:
                    meta.children[k] = merged
        else:
            _, pos = _decode_value(buf, pos, n, wt, depth, max_depth, is_elem=False)
    return meta


def _decode_value(
    buf: memoryview,
    pos: int,
    end: int,
    wt: int,
    depth: int,
    max_depth: int,
    *,
    is_elem: bool,
) -> tuple[Any, int]:
    if wt == WIRE_UINT:
        return _decode_varint(buf, pos, end)
    if wt == WIRE_SINT:
        raw_u, next_pos = _decode_varint(buf, pos, end)
        return _decode_zigzag(raw_u), next_pos
    if wt == WIRE_BOOL_FALSE:
        if is_elem:
            if pos >= end:
                raise OmniBufDecodeError("truncated bool element")
            b = buf[pos]
            if b > 1:
                raise OmniBufDecodeError(f"invalid bool byte 0x{b:02x}")
            return b == 1, pos + 1
        return False, pos
    if wt == WIRE_BOOL_TRUE:
        if is_elem:
            raise OmniBufDecodeError("WireBoolTrue invalid as container element type")
        return True, pos
    if wt == WIRE_FIXED32:
        if pos + 4 > end:
            raise OmniBufDecodeError("truncated fixed32")
        return int(_U32_LE.unpack_from(buf, pos)[0]), pos + 4
    if wt == WIRE_FIXED64:
        if pos + 8 > end:
            raise OmniBufDecodeError("truncated fixed64")
        return int(_U64_LE.unpack_from(buf, pos)[0]), pos + 8
    if wt == WIRE_SFIXED32:
        if pos + 4 > end:
            raise OmniBufDecodeError("truncated sfixed32")
        return int(_I32_LE.unpack_from(buf, pos)[0]), pos + 4
    if wt == WIRE_SFIXED64:
        if pos + 8 > end:
            raise OmniBufDecodeError("truncated sfixed64")
        return int(_I64_LE.unpack_from(buf, pos)[0]), pos + 8
    if wt == WIRE_FLOAT32:
        if pos + 4 > end:
            raise OmniBufDecodeError("truncated float32")
        return float(_F32_LE.unpack_from(buf, pos)[0]), pos + 4
    if wt == WIRE_FLOAT64:
        if pos + 8 > end:
            raise OmniBufDecodeError("truncated float64")
        return float(_F64_LE.unpack_from(buf, pos)[0]), pos + 8
    if wt == WIRE_STRING:
        raw, next_pos = _read_len_slice(buf, pos, end, 0)
        return _decode_utf8(raw, pos), next_pos
    if wt == WIRE_BYTES:
        raw, next_pos = _read_len_slice(buf, pos, end, 0)
        return bytes(raw), next_pos
    if wt == WIRE_SUB_MSG:
        if depth + 1 > max_depth:
            raise OmniBufDecodeError(f"nesting depth {depth + 1} exceeds {max_depth}")
        body, next_pos = _read_len_slice(buf, pos, end, 0)
        return _decode_message_mv(body, depth + 1, max_depth), next_pos
    if wt == WIRE_ARRAY:
        if depth + 1 > max_depth:
            raise OmniBufDecodeError(f"array depth {depth + 1} exceeds {max_depth}")
        body, next_pos = _read_len_slice(buf, pos, end, 2)
        elem_wt = body[0]
        if elem_wt > WIRE_EXTENDED or elem_wt == WIRE_BOOL_TRUE:
            raise OmniBufDecodeError(f"invalid array element wire type {elem_wt}")
        count, p = _decode_varint(body, 1, len(body))
        rem = len(body) - p
        if elem_wt == WIRE_BOOL_FALSE:
            ok = count == rem
        elif elem_wt in (WIRE_FIXED32, WIRE_SFIXED32, WIRE_FLOAT32):
            ok = (rem & 3) == 0 and count == (rem >> 2)
        elif elem_wt in (WIRE_FIXED64, WIRE_SFIXED64, WIRE_FLOAT64):
            ok = (rem & 7) == 0 and count == (rem >> 3)
        else:
            ok = (rem == 0) if count == 0 else (count <= rem)
        if not ok:
            raise OmniBufDecodeError("invalid array count")
        items: list[Any] = []
        for _ in range(count):
            val, p = _decode_value(body, p, len(body), elem_wt, depth + 1, max_depth, is_elem=True)
            items.append(val)
        if p != len(body):
            raise OmniBufDecodeError("trailing bytes in array")
        return DecodedArray(elem_wire_type=elem_wt, count=count, items=items), next_pos
    if wt == WIRE_MAP:
        if depth + 1 > max_depth:
            raise OmniBufDecodeError(f"map depth {depth + 1} exceeds {max_depth}")
        body, next_pos = _read_len_slice(buf, pos, end, 3)
        key_wt, val_wt = body[0], body[1]
        if key_wt not in VALID_MAP_KEY_TYPES or val_wt > WIRE_EXTENDED or val_wt == WIRE_BOOL_TRUE:
            raise OmniBufDecodeError(f"invalid map types ({key_wt}, {val_wt})")
        count, p = _decode_varint(body, 2, len(body))
        rem = len(body) - p
        if (count == 0 and rem != 0) or (count > 0 and count > (rem >> 1)):
            raise OmniBufDecodeError("invalid map count")
        entries: list[tuple[Any, Any]] = []
        for _ in range(count):
            kval, p = _decode_value(body, p, len(body), key_wt, depth + 1, max_depth, is_elem=True)
            vval, p = _decode_value(body, p, len(body), val_wt, depth + 1, max_depth, is_elem=True)
            entries.append((kval, vval))
        if p != len(body):
            raise OmniBufDecodeError("trailing bytes in map")
        return DecodedMap(key_wire_type=key_wt, val_wire_type=val_wt, count=count, entries=entries), next_pos
    if wt == WIRE_EXTENDED:
        body, next_pos = _read_len_slice(buf, pos, end, 1)
        return DecodedExtended(subtype=body[0], payload=bytes(body[1:])), next_pos
    raise OmniBufDecodeError(f"unknown wire type {wt}")


def _canonical_wt(wt: int) -> int:
    return WIRE_BOOL_FALSE if wt == WIRE_BOOL_TRUE else wt


def _array_shape_key(val: DecodedArray) -> str:
    parts = [str(_canonical_wt(val.elem_wire_type))]
    if val.elem_wire_type == WIRE_ARRAY:
        inner: str | None = None
        for item in val.items:
            if not isinstance(item, DecodedArray):
                continue
            s = _array_shape_key(item)
            if inner is None:
                inner = s
            elif inner != s:
                raise OmniBufDecodeError("conflicting nested WireArray element types")
        if inner is not None:
            parts.append(inner)
    return ">".join(parts)


def _field_shape_key(wt: int, val: Any) -> str:
    cwt = _canonical_wt(wt)
    if cwt == WIRE_ARRAY and isinstance(val, DecodedArray):
        return f"A:{_array_shape_key(val)}"
    if cwt == WIRE_MAP and isinstance(val, DecodedMap):
        return f"M:{_canonical_wt(val.key_wire_type)}:{_canonical_wt(val.val_wire_type)}"
    return str(cwt)


def _decode_message_mv(
    buf: memoryview, depth: int = 0, max_depth: int = MAX_CONTAINER_DEPTH
) -> DecodedMessage:
    n = len(buf)
    pos = 0
    fields: list[DecodedField] = []
    seen_shapes: dict[int, str] = {}
    merged_meta: SchemaMeta | None = None
    while pos < n:
        start = pos
        fnum, wt, pos = _decode_tag(buf, pos, n)
        if fnum == 0:
            if depth + 1 > max_depth:
                raise OmniBufDecodeError("Field #0 exceeds max depth")
            body, pos = _read_len_slice(buf, pos, n, 0)
            meta = _decode_schema_meta(body, depth + 1, max_depth)
            merged_meta = _merge_schema_meta(merged_meta, meta)
            fields.append(DecodedField(0, wt, start, pos, meta))
        else:
            val, pos = _decode_value(buf, pos, n, wt, depth, max_depth, is_elem=False)
            shape = _field_shape_key(wt, val)
            prev = seen_shapes.get(fnum)
            if prev is not None and prev != shape:
                raise OmniBufDecodeError(f"field #{fnum} shape mismatch ({prev} vs {shape})")
            seen_shapes[fnum] = shape
            fields.append(DecodedField(fnum, wt, start, pos, val))
    if merged_meta is not None:
        used_names: dict[str, int] = {}
        for fn, name in merged_meta.fields.items():
            if not name:
                continue
            if name in used_names and used_names[name] != fn:
                raise OmniBufDecodeError(
                    f"Field #0 duplicate field name {name!r} for #{used_names[name]} and #{fn}"
                )
            used_names[name] = fn
    return DecodedMessage(fields=fields, schema_meta=merged_meta)


def decode_message(data: bytes | bytearray | memoryview) -> DecodedMessage:
    """Decodes an OmniBuf message payload without requiring a schema."""
    return _decode_message_mv(memoryview(data), 0, MAX_CONTAINER_DEPTH)


def decode_envelope_frames(data: bytes | bytearray | memoryview) -> list[EnvelopeFrame]:
    """Peels 5-byte Connect/gRPC length-prefixed framing envelopes."""
    mv = memoryview(data)
    n = len(mv)
    pos = 0
    frames: list[EnvelopeFrame] = []
    while pos < n:
        if pos + 5 > n:
            raise OmniBufDecodeError(f"truncated 5-byte envelope header at byte {pos}")
        flags, length = _ENV_HDR.unpack_from(mv, pos)
        pos += 5
        if pos + length > n:
            raise OmniBufDecodeError(
                f"truncated envelope payload: need {length} bytes, have {n - pos}"
            )
        frames.append(EnvelopeFrame(flags=flags, length=length, payload=bytes(mv[pos : pos + length])))
        pos += length
    return frames


# ---------------------------------------------------------------------------
# Schema overlay loader (lightweight OmniBuf JSON & FileDescriptorSet JSON)
# ---------------------------------------------------------------------------


def _trim_dot(name: str | None) -> str | None:
    if name and name.startswith("."):
        return name[1:]
    return name


def _get_json_list(obj: dict[str, Any], camel_key: str, snake_key: str) -> list[Any]:
    val = obj.get(camel_key)
    if isinstance(val, list):
        return val
    val = obj.get(snake_key)
    if isinstance(val, list):
        return val
    return []


def _is_editions_file(fdesc: dict[str, Any]) -> bool:
    if fdesc.get("syntax") == "editions":
        return True
    edition = fdesc.get("edition")
    if isinstance(edition, str):
        return edition.startswith("EDITION_20")
    if isinstance(edition, int) and not isinstance(edition, bool):
        return edition >= 1000
    return False


def _is_message_field_type(ftype: Any, is_editions: bool) -> bool:
    return ftype in ("TYPE_MESSAGE", 11) or (is_editions and ftype in ("TYPE_GROUP", 10))


def load_schema_json(raw_json: str) -> SchemaOverlay:
    """Loads either a lightweight OmniBuf JSON schema or a Protobuf FileDescriptorSet JSON."""
    doc = json.loads(raw_json)
    if not isinstance(doc, dict):
        raise TypeError("schema JSON root must be an object")

    overlay = SchemaOverlay(root=_trim_dot(doc.get("root")))

    if isinstance(doc.get("messages"), dict):
        for msg_name, msg_def in doc["messages"].items():
            src_fields = msg_def.get("fields", msg_def) if isinstance(msg_def, dict) else {}
            ftable: dict[int, FieldSchema] = {}
            for k, v in src_fields.items():
                fnum = int(k)
                if isinstance(v, str):
                    ftable[fnum] = FieldSchema(name=v)
                elif isinstance(v, dict):
                    ftable[fnum] = FieldSchema(
                        name=v.get("name"),
                        message=_trim_dot(v.get("message")),
                        enum=_trim_dot(v.get("enum")),
                    )
            overlay.messages[_trim_dot(msg_name) or msg_name] = ftable
        if isinstance(doc.get("enums"), dict):
            for enum_name, enum_def in doc["enums"].items():
                etable = {int(k): str(v) for k, v in enum_def.items()}
                overlay.enums[_trim_dot(enum_name) or enum_name] = etable
        return overlay

    if isinstance(doc.get("file"), list):
        map_entries: dict[str, tuple[str | None, str | None]] = {}
        fallback_root: str | None = None

        def index_enum(prefix: str, edesc: dict[str, Any]) -> None:
            full = f"{prefix}.{edesc['name']}" if prefix else edesc["name"]
            overlay.enums[full] = {
                int(v["number"]): str(v["name"])
                for v in (edesc.get("value") or [])
                if "number" in v and "name" in v
            }

        def index_message(prefix: str, mdesc: dict[str, Any], is_editions: bool) -> None:
            nonlocal fallback_root
            full = f"{prefix}.{mdesc['name']}" if prefix else mdesc["name"]
            opts = mdesc.get("options")
            is_map_entry = isinstance(opts, dict) and bool(
                opts.get("mapEntry") or opts.get("map_entry")
            )
            if is_map_entry:
                val_msg: str | None = None
                val_enum: str | None = None
                for f in mdesc.get("field") or []:
                    if int(f["number"]) == 2:
                        ftype = f.get("type")
                        tname = _trim_dot(f.get("typeName") or f.get("type_name"))
                        if _is_message_field_type(ftype, is_editions):
                            val_msg = tname
                        elif ftype in ("TYPE_ENUM", 14):
                            val_enum = tname
                        break
                map_entries[full] = (val_msg, val_enum)
                return

            ftable: dict[int, FieldSchema] = {}
            for f in mdesc.get("field") or []:
                fnum = int(f["number"])
                ftype = f.get("type")
                tname = _trim_dot(f.get("typeName") or f.get("type_name"))
                ftable[fnum] = FieldSchema(
                    name=f.get("name"),
                    message=tname if _is_message_field_type(ftype, is_editions) else None,
                    enum=tname if ftype in ("TYPE_ENUM", 14) else None,
                )
            overlay.messages[full] = ftable
            if overlay.root is None:
                if not full.startswith("google.protobuf."):
                    overlay.root = full
                elif fallback_root is None:
                    fallback_root = full
            for e in _get_json_list(mdesc, "enumType", "enum_type"):
                index_enum(full, e)
            for nested in _get_json_list(mdesc, "nestedType", "nested_type"):
                index_message(full, nested, is_editions)

        for fdesc in doc["file"]:
            pkg = fdesc.get("package") or ""
            is_editions = _is_editions_file(fdesc)
            for e in _get_json_list(fdesc, "enumType", "enum_type"):
                index_enum(pkg, e)
            for m in _get_json_list(fdesc, "messageType", "message_type"):
                index_message(pkg, m, is_editions)

        if overlay.root is None:
            overlay.root = fallback_root
        if map_entries:
            for ftable in overlay.messages.values():
                for fschema in ftable.values():
                    if fschema.message and fschema.message in map_entries:
                        fschema.message, fschema.enum = map_entries[fschema.message]
        return overlay

    raise ValueError("unrecognized schema JSON format (expected 'messages' or 'file')")


def load_schema_file(path: str | Path) -> SchemaOverlay:
    return load_schema_json(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Structured formatting for mitmproxy TViewResult & plain text
# ---------------------------------------------------------------------------

# TViewLine is list[tuple[str, str]] in mitmproxy (token_style, text)
TViewLine = list[tuple[str, str]]


def _format_scalar(wt: int, val: Any, enum_table: dict[int, str] | None = None) -> tuple[str, str]:
    if wt in (WIRE_UINT, WIRE_SINT, WIRE_FIXED32, WIRE_FIXED64, WIRE_SFIXED32, WIRE_SFIXED64):
        if enum_table and val in enum_table:
            return "text", f"{enum_table[val]} ({val})"
        return "number", str(val)
    if wt in (WIRE_BOOL_FALSE, WIRE_BOOL_TRUE):
        return "boolean", "true" if val else "false"
    if wt in (WIRE_FLOAT32, WIRE_FLOAT64):
        return "number", f"{val:.9g}"
    if wt == WIRE_STRING:
        return "string", json.dumps(val, ensure_ascii=False)
    if wt == WIRE_BYTES:
        hex_preview = val[:24].hex()
        suffix = "..." if len(val) > 24 else ""
        return "text", f"0x{hex_preview}{suffix} ({len(val)} bytes)"
    if isinstance(val, DecodedExtended):
        return "text", f"extended(subtype=0x{val.subtype:02x}, {len(val.payload)} bytes)"
    return "text", repr(val)


def format_message_lines(
    msg: DecodedMessage,
    schema: SchemaOverlay | None = None,
    msg_name: str | None = None,
    meta: SchemaMeta | None = None,
    indent: int = 0,
) -> list[TViewLine]:
    lines: list[TViewLine] = []
    pad = "  " * indent
    eff_meta = _merge_schema_meta(meta, msg.schema_meta)
    eff_name = msg_name or (eff_meta.type_name if eff_meta and eff_meta.type_name else None)
    if eff_name is None and indent == 0 and schema:
        eff_name = schema.root
    msg_fields = schema.messages.get(eff_name) if (schema and eff_name) else None

    if indent == 0 and eff_name:
        lines.append([("header", f"# {eff_name}")])

    for f in msg.fields:
        if f.field_num == 0 and isinstance(f.value, SchemaMeta):
            label = f"SchemaMeta ({f.value.type_name})" if f.value.type_name else "SchemaMeta"
            lines.append(
                [
                    ("text", pad),
                    ("offset", "#0 "),
                    ("comment", f"[{WIRE_TYPE_NAMES[f.wire_type]}] {label}"),
                ]
            )
            continue

        fdef = msg_fields.get(f.field_num) if msg_fields else None
        fname = (fdef.name if fdef and fdef.name else None) or (
            eff_meta.fields.get(f.field_num) if eff_meta else None
        )
        child_msg = fdef.message if fdef else None
        child_meta = eff_meta.children.get(f.field_num) if eff_meta else None
        enum_table = schema.enums.get(fdef.enum) if (schema and fdef and fdef.enum) else None

        prefix: TViewLine = [("text", pad), ("offset", f"#{f.field_num} ")]
        if fname:
            prefix.append(("key", f"{fname} "))
        prefix.append(("comment", f"({WIRE_TYPE_NAMES.get(f.wire_type, str(f.wire_type))})"))

        val = f.value
        if isinstance(val, DecodedMessage):
            lines.append(prefix + [("text", " {")])
            lines.extend(
                format_message_lines(val, schema, child_msg, child_meta, indent=indent + 1)
            )
            lines.append([("text", f"{pad}}}")])
        elif isinstance(val, DecodedArray):
            ewt_name = WIRE_TYPE_NAMES.get(val.elem_wire_type, str(val.elem_wire_type))
            lines.append(prefix + [("text", f" [{val.count} x {ewt_name}] [")])
            for idx, item in enumerate(val.items):
                item_pad = "  " * (indent + 1)
                if isinstance(item, DecodedMessage):
                    lines.append([("text", item_pad), ("offset", f"[{idx}]"), ("text", " {")])
                    lines.extend(
                        format_message_lines(item, schema, child_msg, child_meta, indent=indent + 2)
                    )
                    lines.append([("text", f"{item_pad}}}")])
                else:
                    style, text = _format_scalar(val.elem_wire_type, item, enum_table)
                    lines.append([("text", item_pad), ("offset", f"[{idx}] "), (style, text)])
            lines.append([("text", f"{pad}]")])
        elif isinstance(val, DecodedMap):
            k_name = WIRE_TYPE_NAMES.get(val.key_wire_type, str(val.key_wire_type))
            v_name = WIRE_TYPE_NAMES.get(val.val_wire_type, str(val.val_wire_type))
            lines.append(prefix + [("text", f" map<{k_name}, {v_name}> {{")])
            for k, v in val.entries:
                ep = "  " * (indent + 1)
                _, k_text = _format_scalar(val.key_wire_type, k)
                if isinstance(v, DecodedMessage):
                    lines.append([("text", ep), ("key", k_text), ("text", ": {")])
                    lines.extend(
                        format_message_lines(v, schema, child_msg, child_meta, indent=indent + 2)
                    )
                    lines.append([("text", f"{ep}}}")])
                else:
                    style, v_text = _format_scalar(val.val_wire_type, v, enum_table)
                    lines.append([("text", ep), ("key", k_text), ("text", ": "), (style, v_text)])
            lines.append([("text", f"{pad}}}")])
        else:
            style, text = _format_scalar(f.wire_type, val, enum_table)
            lines.append(prefix + [("text", ": "), (style, text)])

    return lines


def format_payload(
    data: bytes,
    content_type: str = "",
    schema: SchemaOverlay | None = None,
) -> tuple[str, list[TViewLine]]:
    """Decodes an OmniBuf or Connect/gRPC-framed OmniBuf payload into (title, TViewLines)."""
    media = content_type.split(";", 1)[0].strip().lower()
    is_envelope = media in ENVELOPE_MEDIA_TYPES

    if is_envelope:
        frames = decode_envelope_frames(data)
        lines: list[TViewLine] = []
        for idx, frame in enumerate(frames, start=1):
            flags_desc: list[str] = [f"flags=0x{frame.flags:02x}", f"{frame.length} bytes"]
            if frame.compressed:
                flags_desc.append("compressed")
            if frame.end_stream:
                flags_desc.append("end-stream")
            lines.append([("header", f"--- Frame #{idx} ({', '.join(flags_desc)}) ---")])
            payload = frame.payload
            if frame.compressed and payload:
                try:
                    payload = gzip.decompress(payload)
                except OSError:
                    lines.append([("error", "  <compressed payload: unable to gzip-decompress>")])
                    continue
            if frame.end_stream:
                try:
                    text = payload.decode("utf-8", "strict")
                    lines.append([("string", f"  {text}")])
                except UnicodeDecodeError:
                    lines.append([("text", f"  0x{payload.hex()}")])
                continue
            if not payload:
                lines.append([("comment", "  <empty message>")])
                continue
            msg = decode_message(payload)
            lines.extend(format_message_lines(msg, schema=schema, indent=1))
        title = f"OmniBuf Stream ({len(frames)} frame{'s' if len(frames) != 1 else ''})"
        return title, lines

    msg = decode_message(data)
    lines = format_message_lines(msg, schema=schema)
    title = f"OmniBuf ({len(msg.fields)} field{'s' if len(msg.fields) != 1 else ''})"
    return title, lines


def lines_to_text(lines: list[TViewLine]) -> str:
    """Flattens TViewLine tuples to plain text (for mitmproxy 12+ and CLI output)."""
    return "\n".join("".join(seg for _, seg in line) for line in lines)


# ---------------------------------------------------------------------------
# mitmproxy integration (supports both mitmproxy 10/11 View and 12+ Contentview)
# ---------------------------------------------------------------------------

_ACTIVE_SCHEMA: SchemaOverlay | None = None
_ACTIVE_SCHEMA_PATH: str = ""


def _reload_schema(path: str) -> None:
    global _ACTIVE_SCHEMA, _ACTIVE_SCHEMA_PATH
    if path == _ACTIVE_SCHEMA_PATH:
        return
    _ACTIVE_SCHEMA_PATH = path
    if not path:
        _ACTIVE_SCHEMA = None
        return
    _ACTIVE_SCHEMA = load_schema_file(path)


def _match_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media in OMNIBUF_MEDIA_TYPES


try:
    from mitmproxy import contentviews, ctx

    if hasattr(contentviews, "Contentview"):
        # mitmproxy 12+ API (Contentview)
        class OmniBufContentview(contentviews.Contentview):  # type: ignore[misc]
            name = "OmniBuf"
            syntax_highlight = "yaml"

            def prettify(self, data: bytes, metadata: Any) -> str:
                ct = getattr(metadata, "content_type", "") or ""
                title, lines = format_payload(data, content_type=ct, schema=_ACTIVE_SCHEMA)
                return f"# {title}\n{lines_to_text(lines)}"

            def render_priority(self, data: bytes, metadata: Any) -> float:
                ct = getattr(metadata, "content_type", "") or ""
                return 2.0 if _match_content_type(ct) else 0.0

        _VIEW_INSTANCE: Any = OmniBufContentview()
    else:
        # mitmproxy 10 / 11 API (View subclass returning TViewResult)
        class ViewOmniBuf(contentviews.View):  # type: ignore[misc]
            name = "OmniBuf"
            content_types: ClassVar[list[str]] = list(OMNIBUF_MEDIA_TYPES)

            def __call__(
                self,
                data: bytes,
                *,
                content_type: str | None = None,
                flow: Any = None,
                http_message: Any = None,
                **metadata: Any,
            ) -> tuple[str, Iterator[TViewLine]]:
                ct = content_type or ""
                if not ct and http_message is not None and hasattr(http_message, "headers"):
                    ct = http_message.headers.get("content-type", "")
                title, lines = format_payload(data, content_type=ct, schema=_ACTIVE_SCHEMA)
                return title, iter(lines)

        _VIEW_INSTANCE = ViewOmniBuf()

    class OmniBufAddon:
        """mitmproxy addon registering the OmniBuf ContentView and `--set omnibuf_schema` option."""

        def load(self, loader: Any) -> None:
            loader.add_option(
                name="omnibuf_schema",
                typespec=str,
                default="",
                help="Path to an OmniBuf JSON schema or Protobuf FileDescriptorSet JSON file.",
            )
            contentviews.add(_VIEW_INSTANCE)

        def configure(self, updates: set[str]) -> None:
            if "omnibuf_schema" in updates:
                path = getattr(ctx.options, "omnibuf_schema", "")
                try:
                    _reload_schema(path)
                except (OSError, ValueError, TypeError) as exc:
                    ctx.log.error(f"omnibuf_mitmproxy: failed to load schema '{path}': {exc}")

        def done(self) -> None:
            if hasattr(contentviews, "remove"):
                with contextlib.suppress(KeyError, ValueError):
                    contentviews.remove(_VIEW_INSTANCE)

    addons = [OmniBufAddon()]

except ImportError:
    # Allows importing decoder & formatting helpers outside a mitmproxy environment.
    addons = []
