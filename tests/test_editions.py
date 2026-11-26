"""Protobuf Editions 2023, 2024, and 2026 FileDescriptorSet JSON schema overlay tests."""

from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

import omnibuf_mitmproxy as om


def _encode_varint(v: int) -> bytes:
    if v <= 127:
        return bytes([(v << 1) | 1])
    if v <= 16383:
        return struct.pack("<H", (v << 2) | 2)
    if v <= 536_870_911:
        return struct.pack("<I", (v << 3) | 4)
    return struct.pack("<BQ", 0, v)


def _encode_tag(fnum: int, wt: int) -> bytes:
    return _encode_varint((fnum << 4) | wt)


def _encode_uint(fnum: int, val: int) -> bytes:
    return _encode_tag(fnum, om.WIRE_UINT) + _encode_varint(val)


def _encode_sint(fnum: int, val: int) -> bytes:
    zz = ((val << 1) ^ (val >> 63)) & 0xFFFFFFFFFFFFFFFF
    return _encode_tag(fnum, om.WIRE_SINT) + _encode_varint(zz)


def _encode_bool(fnum: int, val: bool) -> bytes:
    return _encode_tag(fnum, om.WIRE_BOOL_TRUE if val else om.WIRE_BOOL_FALSE)


def _encode_string(fnum: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return _encode_tag(fnum, om.WIRE_STRING) + _encode_varint(len(raw)) + raw


def _encode_bytes(fnum: int, raw: bytes) -> bytes:
    return _encode_tag(fnum, om.WIRE_BYTES) + _encode_varint(len(raw)) + raw


def _encode_submsg(fnum: int, body: bytes) -> bytes:
    return _encode_tag(fnum, om.WIRE_SUB_MSG) + _encode_varint(len(body)) + body


def _encode_array(fnum: int, elem_wt: int, items: list[bytes]) -> bytes:
    body = bytes([elem_wt]) + _encode_varint(len(items)) + b"".join(items)
    return _encode_tag(fnum, om.WIRE_ARRAY) + _encode_varint(len(body)) + body


def _encode_map(fnum: int, key_wt: int, val_wt: int, entries: list[tuple[bytes, bytes]]) -> bytes:
    body = bytearray([key_wt, val_wt])
    body.extend(_encode_varint(len(entries)))
    for k_raw, v_raw in entries:
        body.extend(k_raw)
        body.extend(v_raw)
    return _encode_tag(fnum, om.WIRE_MAP) + _encode_varint(len(body)) + bytes(body)


def _encode_len_prefixed(raw: bytes) -> bytes:
    return _encode_varint(len(raw)) + raw


def _encode_zigzag_elem(val: int) -> bytes:
    zz = ((val << 1) ^ (val >> 63)) & 0xFFFFFFFFFFFFFFFF
    return _encode_varint(zz)


def _encode_child(child_id: int, label: str) -> bytes:
    return _encode_sint(1, child_id) + _encode_string(2, label)


def _editions_record_wire_bytes() -> bytes:
    """Encodes a Record exercising explicit-presence zero/false/empty, open enums, delimited, and maps."""
    lp_child = _encode_child(0, "")
    delim_child = _encode_child(42, "delim")
    delim_list = [
        _encode_len_prefixed(_encode_child(1, "first")),
        _encode_len_prefixed(_encode_child(2, "second")),
    ]
    scores = [
        (_encode_len_prefixed(b"zero"), _encode_zigzag_elem(0)),
        (_encode_len_prefixed(b"neg"), _encode_zigzag_elem(-5)),
    ]
    children_by_key = [
        (_encode_len_prefixed(b"primary"), _encode_len_prefixed(_encode_child(7, "edge"))),
    ]
    statuses = [
        (_encode_len_prefixed(b"init"), _encode_varint(0)),
        (_encode_len_prefixed(b"ready"), _encode_varint(1)),
        (_encode_len_prefixed(b"future"), _encode_varint(99)),
    ]
    oo_delim = _encode_child(9, "oneof")
    status_list = [_encode_varint(0), _encode_varint(1), _encode_varint(77)]

    return b"".join(
        [
            _encode_sint(1, 0),
            _encode_bool(2, False),
            _encode_string(3, ""),
            _encode_bytes(4, b""),
            _encode_uint(5, 0),
            _encode_uint(6, 99),
            _encode_sint(7, -7),
            _encode_submsg(8, lp_child),
            _encode_submsg(9, delim_child),
            _encode_array(10, om.WIRE_SUB_MSG, delim_list),
            _encode_map(11, om.WIRE_STRING, om.WIRE_SINT, scores),
            _encode_map(12, om.WIRE_STRING, om.WIRE_SUB_MSG, children_by_key),
            _encode_map(13, om.WIRE_STRING, om.WIRE_UINT, statuses),
            _encode_submsg(14, oo_delim),
            _encode_array(15, om.WIRE_UINT, status_list),
        ]
    )


def _assert_rendered_record(schema: om.SchemaOverlay, pkg: str) -> None:
    record_name = f"{pkg}.Record"
    child_name = f"{pkg}.Child"
    enum_name = f"{pkg}.OpenStatus"

    assert record_name in schema.messages
    assert child_name in schema.messages
    assert enum_name in schema.enums
    assert schema.root != "google.protobuf.FileDescriptorSet"

    rec_fields = schema.messages[record_name]
    assert rec_fields[8].message == child_name
    assert rec_fields[9].message == child_name
    assert rec_fields[10].message == child_name
    assert rec_fields[11].message is None and rec_fields[11].enum is None
    assert rec_fields[12].message == child_name and rec_fields[12].enum is None
    assert rec_fields[13].message is None and rec_fields[13].enum == enum_name
    assert rec_fields[14].message == child_name
    assert rec_fields[15].enum == enum_name

    # Synthetic map entry messages should not pollute overlay.messages.
    assert f"{record_name}.ChildrenByKeyEntry" not in schema.messages
    assert f"{record_name}.StatusesEntry" not in schema.messages

    msg = om.decode_message(_editions_record_wire_bytes())
    lines = om.format_message_lines(msg, schema=schema, msg_name=record_name)
    text = om.lines_to_text(lines)

    assert f"# {record_name}" in text
    assert "#1 exp_i32 (sint): 0" in text
    assert "#2 exp_bool (bool): false" in text
    assert '#3 exp_str (string): ""' in text
    assert "#4 exp_bytes (bytes): 0x (0 bytes)" in text
    assert "#5 exp_enum (uint): OPEN_STATUS_UNSPECIFIED (0)" in text
    assert "#6 unknown_enum (uint): 99" in text
    assert "#7 neg_unknown_enum (sint): -7" in text
    assert "#8 lp_child (submsg) {" in text
    assert "#1 id (sint): 0" in text
    assert '#2 label (string): ""' in text
    assert "#9 delim_child (submsg) {" in text
    assert "#1 id (sint): 42" in text
    assert '#2 label (string): "delim"' in text
    assert "#10 delim_list (array) [2 x submsg] [" in text
    assert '#2 label (string): "first"' in text
    assert '#2 label (string): "second"' in text
    assert "#11 scores (map) map<string, sint> {" in text
    assert '"zero": 0' in text
    assert '"neg": -5' in text
    assert "#12 children_by_key (map) map<string, submsg> {" in text
    assert '"primary": {' in text
    assert "#1 id (sint): 7" in text
    assert '#2 label (string): "edge"' in text
    assert "#13 statuses (map) map<string, uint> {" in text
    assert '"init": OPEN_STATUS_UNSPECIFIED (0)' in text
    assert '"ready": OPEN_STATUS_READY (1)' in text
    assert '"future": 99' in text
    assert "#14 oo_delim (submsg) {" in text
    assert "#1 id (sint): 9" in text
    assert '#2 label (string): "oneof"' in text
    assert "#15 status_list (array) [3 x uint] [" in text
    assert "[0] OPEN_STATUS_UNSPECIFIED (0)" in text
    assert "[1] OPEN_STATUS_READY (1)" in text
    assert "[2] 77" in text


def _build_editions_proto(edition_str: str, pkg: str, include_descriptor_import: bool = False) -> str:
    export_kw = "export " if edition_str in ("2024", "2026") else ""
    extra_opts = ""
    if edition_str == "2024":
        extra_opts = "option features.enforce_naming_style = STYLE2024;\n"
    elif edition_str == "2026":
        extra_opts = (
            "option features.enforce_naming_style = STYLE2026;\n"
            "option features.default_symbol_visibility = STRICT;\n"
        )
    descriptor_block = ""
    if include_descriptor_import:
        ext_num = {"2023": 51201, "2024": 51202, "2026": 51203}[edition_str]
        descriptor_block = (
            'import "google/protobuf/descriptor.proto";\n'
            f"extend google.protobuf.MessageOptions {{\n  string custom_tag{edition_str} = {ext_num};\n}}\n"
        )
    msg_opt = (
        f'  option (custom_tag{edition_str}) = "ed-{edition_str}";\n'
        if include_descriptor_import
        else ""
    )

    return f"""edition = "{edition_str}";
package {pkg};

{descriptor_block}{extra_opts}
{export_kw}enum OpenStatus {{
  OPEN_STATUS_UNSPECIFIED = 0;
  OPEN_STATUS_READY = 1;
}}

{export_kw}message Child {{
  sint32 id = 1;
  string label = 2 [features.field_presence = IMPLICIT];
}}

{export_kw}message Record {{
{msg_opt}  sint32 exp_i32 = 1;
  bool exp_bool = 2;
  string exp_str = 3;
  bytes exp_bytes = 4;
  OpenStatus exp_enum = 5;
  OpenStatus unknown_enum = 6;
  OpenStatus neg_unknown_enum = 7;
  Child lp_child = 8;
  Child delim_child = 9 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 10 [features.message_encoding = DELIMITED];
  map<string, sint32> scores = 11;
  map<string, Child> children_by_key = 12;
  map<string, OpenStatus> statuses = 13;
  oneof payload {{
    Child oo_delim = 14 [features.message_encoding = DELIMITED];
  }}
  repeated OpenStatus status_list = 15;
}}
"""


def _build_synthetic_editions_fds(
    edition_val: str | int,
    pkg: str,
    *,
    snake_case: bool,
    delimited_type: str | int,
    msg_type: str | int = "TYPE_MESSAGE",
    enum_type: str | int = "TYPE_ENUM",
    include_descriptor_stub: bool = False,
) -> str:
    k_msg = "message_type" if snake_case else "messageType"
    k_enum = "enum_type" if snake_case else "enumType"
    k_nested = "nested_type" if snake_case else "nestedType"
    k_tname = "type_name" if snake_case else "typeName"
    k_map_entry = "map_entry" if snake_case else "mapEntry"

    def map_entry_msg(name: str, val_type: str | int, val_tname: str | None = None) -> dict[str, Any]:
        val_field: dict[str, Any] = {"name": "value", "number": 2, "type": val_type}
        if val_tname is not None:
            val_field[k_tname] = val_tname
        return {
            "name": name,
            "field": [
                {"name": "key", "number": 1, "type": "TYPE_STRING"},
                val_field,
            ],
            "options": {k_map_entry: True},
        }

    files: list[dict[str, Any]] = []
    if include_descriptor_stub:
        files.append(
            {
                "name": "google/protobuf/descriptor.proto",
                "package": "google.protobuf",
                "syntax": "proto2",
                k_msg: [{"name": "FileDescriptorSet", "field": []}],
            }
        )

    files.append(
        {
            "name": f"{pkg}.proto",
            "package": pkg,
            "syntax": "editions",
            "edition": edition_val,
            k_enum: [
                {
                    "name": "OpenStatus",
                    "value": [
                        {"name": "OPEN_STATUS_UNSPECIFIED", "number": 0},
                        {"name": "OPEN_STATUS_READY", "number": 1},
                    ],
                }
            ],
            k_msg: [
                {
                    "name": "Record",
                    "field": [
                        {"name": "exp_i32", "number": 1, "type": "TYPE_SINT32"},
                        {"name": "exp_bool", "number": 2, "type": "TYPE_BOOL"},
                        {"name": "exp_str", "number": 3, "type": "TYPE_STRING"},
                        {"name": "exp_bytes", "number": 4, "type": "TYPE_BYTES"},
                        {"name": "exp_enum", "number": 5, "type": enum_type, k_tname: f".{pkg}.OpenStatus"},
                        {"name": "unknown_enum", "number": 6, "type": enum_type, k_tname: f".{pkg}.OpenStatus"},
                        {"name": "neg_unknown_enum", "number": 7, "type": enum_type, k_tname: f".{pkg}.OpenStatus"},
                        {"name": "lp_child", "number": 8, "type": msg_type, k_tname: f".{pkg}.Child"},
                        {"name": "delim_child", "number": 9, "type": delimited_type, k_tname: f".{pkg}.Child"},
                        {"name": "delim_list", "number": 10, "type": delimited_type, k_tname: f".{pkg}.Child"},
                        {"name": "scores", "number": 11, "type": msg_type, k_tname: f".{pkg}.Record.ScoresEntry"},
                        {
                            "name": "children_by_key",
                            "number": 12,
                            "type": msg_type,
                            k_tname: f".{pkg}.Record.ChildrenByKeyEntry",
                        },
                        {
                            "name": "statuses",
                            "number": 13,
                            "type": msg_type,
                            k_tname: f".{pkg}.Record.StatusesEntry",
                        },
                        {"name": "oo_delim", "number": 14, "type": delimited_type, k_tname: f".{pkg}.Child"},
                        {"name": "status_list", "number": 15, "type": enum_type, k_tname: f".{pkg}.OpenStatus"},
                    ],
                    k_nested: [
                        map_entry_msg("ScoresEntry", "TYPE_SINT32"),
                        map_entry_msg("ChildrenByKeyEntry", msg_type, f".{pkg}.Child"),
                        map_entry_msg("StatusesEntry", enum_type, f".{pkg}.OpenStatus"),
                    ],
                },
                {
                    "name": "Child",
                    "field": [
                        {"name": "id", "number": 1, "type": "TYPE_SINT32"},
                        {"name": "label", "number": 2, "type": "TYPE_STRING"},
                    ],
                },
            ],
        }
    )
    return json.dumps({"file": files})


def _semver_key(path: Path) -> tuple[int, ...]:
    m = re.search(r"v?(\d+)\.(\d+)\.(\d+)", str(path))
    if not m:
        return (0, 0, 0)
    return tuple(int(p) for p in m.groups())


def _find_buf_bin() -> str | None:
    found = shutil.which("buf")
    if found:
        probe = subprocess.run([found, "--version"], capture_output=True, text=True, check=False)
        if probe.returncode == 0:
            return found
    mise_root = Path.home() / ".local" / "share" / "mise" / "installs" / "buf"
    try:
        if mise_root.is_dir():
            candidates = sorted(mise_root.glob("**/bin/buf"), key=_semver_key)
            if candidates:
                return str(candidates[-1])
    except OSError:
        return None
    return None


@pytest.mark.parametrize(
    ("edition_val", "pkg", "snake_case", "delimited_type", "msg_type", "enum_type"),
    [
        ("EDITION_2023", "demo.ed2023", False, "TYPE_MESSAGE", "TYPE_MESSAGE", "TYPE_ENUM"),
        ("EDITION_2023", "demo.ed2023", False, "TYPE_GROUP", "TYPE_MESSAGE", "TYPE_ENUM"),
        ("EDITION_2024", "demo.ed2024", True, "TYPE_GROUP", "TYPE_MESSAGE", "TYPE_ENUM"),
        ("EDITION_2026", "demo.ed2026", True, 10, 11, 14),
        (1002, "demo.ed2026num", False, 10, 11, 14),
    ],
)
def test_editions_fds_json_variants(
    edition_val: str | int,
    pkg: str,
    snake_case: bool,
    delimited_type: str | int,
    msg_type: str | int,
    enum_type: str | int,
) -> None:
    raw_json = _build_synthetic_editions_fds(
        edition_val,
        pkg,
        snake_case=snake_case,
        delimited_type=delimited_type,
        msg_type=msg_type,
        enum_type=enum_type,
        include_descriptor_stub=True,
    )
    schema = om.load_schema_json(raw_json)
    assert schema.root == f"{pkg}.Record"
    _assert_rendered_record(schema, pkg)


def test_proto2_type_group_not_treated_as_editions_delimited() -> None:
    raw = json.dumps(
        {
            "file": [
                {
                    "package": "legacy.v1",
                    "syntax": "proto2",
                    "messageType": [
                        {
                            "name": "Holder",
                            "field": [
                                {
                                    "name": "legacy_group",
                                    "number": 1,
                                    "type": "TYPE_GROUP",
                                    "typeName": ".legacy.v1.Holder.LegacyGroup",
                                },
                                {
                                    "name": "legacy_num",
                                    "number": 2,
                                    "type": 10,
                                    "typeName": ".legacy.v1.Holder.LegacyGroup",
                                },
                            ],
                            "nestedType": [
                                {
                                    "name": "LegacyGroup",
                                    "field": [{"name": "x", "number": 1, "type": "TYPE_INT32"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    schema = om.load_schema_json(raw)
    assert schema.messages["legacy.v1.Holder"][1].message is None
    assert schema.messages["legacy.v1.Holder"][2].message is None


@pytest.mark.parametrize("edition_str", ["2023", "2024", "2026"])
def test_editions_live_buf_build_fds_json(tmp_path: Path, edition_str: str) -> None:
    buf_bin = _find_buf_bin()
    if buf_bin is None:
        pytest.skip("buf not installed")
        return

    pkg = f"demo.ed{edition_str}"
    proto_path = tmp_path / f"ed{edition_str}.proto"
    out_json = tmp_path / f"ed{edition_str}.schema.json"
    proto_path.write_text(_build_editions_proto(edition_str, pkg), encoding="utf-8")

    proc = subprocess.run(
        [buf_bin, "build", str(proto_path), "-o", str(out_json)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"buf build failed for edition {edition_str}:\n{proc.stderr}"

    schema = om.load_schema_file(out_json)
    _assert_rendered_record(schema, pkg)


@pytest.mark.parametrize("edition_str", ["2023", "2024", "2026"])
def test_editions_live_protoc_fds_camel_and_snake(tmp_path: Path, edition_str: str) -> None:
    protoc_bin = shutil.which("protoc")
    if protoc_bin is None:
        pytest.skip("protoc not installed")
        return

    pkg = f"demo.protoc_ed{edition_str}"
    proto_path = tmp_path / f"ed{edition_str}.proto"
    fds_pb = tmp_path / f"ed{edition_str}.pb"
    proto_path.write_text(
        _build_editions_proto(edition_str, pkg, include_descriptor_import=True),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            protoc_bin,
            f"-I{tmp_path}",
            "--include_imports",
            f"--descriptor_set_out={fds_pb}",
            str(proto_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"protoc failed for edition {edition_str}:\n{proc.stderr}"

    tested_any = False
    try:
        from google.protobuf import descriptor_pb2, json_format

        fds = descriptor_pb2.FileDescriptorSet()
        fds.ParseFromString(fds_pb.read_bytes())

        camel_json = json_format.MessageToJson(fds, preserving_proto_field_name=False)
        snake_json = json_format.MessageToJson(fds, preserving_proto_field_name=True)

        _assert_rendered_record(om.load_schema_json(camel_json), pkg)
        _assert_rendered_record(om.load_schema_json(snake_json), pkg)
        tested_any = True
    except ImportError:
        pass

    buf_bin = _find_buf_bin()
    if buf_bin is not None:
        buf_json_path = tmp_path / f"ed{edition_str}.from_protoc.json"
        conv = subprocess.run(
            [buf_bin, "build", f"{fds_pb}#format=binpb", "-o", str(buf_json_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert conv.returncode == 0, f"buf binpb->json failed:\n{conv.stderr}"
        _assert_rendered_record(om.load_schema_file(buf_json_path), pkg)
        tested_any = True

    if not tested_any:
        pytest.skip("neither google.protobuf nor buf is installed to serialize protoc FDS to JSON")
