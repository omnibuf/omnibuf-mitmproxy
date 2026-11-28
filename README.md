# omnibuf-mitmproxy

[![CI](https://github.com/omnibuf/omnibuf-mitmproxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/omnibuf/omnibuf-mitmproxy/actions/workflows/ci.yml?query=branch%3Amain)
[![OmniBuf Spec: v1 DRAFT-1](https://img.shields.io/badge/OmniBuf%20Spec-v1%20DRAFT--1-FF4F18)](https://omnibuf.com/spec)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](./LICENSE)
[![Website](https://img.shields.io/badge/website-omnibuf.com-111111?style=flat&labelColor=111111&color=D4FF33)](https://omnibuf.com/tooling/traffic)

`mitmproxy` ContentView addon for inspecting OmniBuf, Connect+OmniBuf, and gRPC+OmniBuf HTTP traffic without configuring `SSLKEYLOGFILE`.

## Quickstart

Run directly as a single script:

```sh
mitmproxy -s omnibuf_mitmproxy.py
```

With an optional schema overlay (lightweight OmniBuf JSON or `buf build -o schema.json`):

```sh
mitmproxy -s omnibuf_mitmproxy.py --set omnibuf_schema=/path/to/schema.json
mitmweb   -s omnibuf_mitmproxy.py --set omnibuf_schema=/path/to/schema.json
```

Install as a Python package (`pip` or `uv`):

```sh
uv pip install mitmproxy-omnibuf
# or
pip install mitmproxy-omnibuf
```

## Supported Media Types

- `application/omnibuf`
- `application/x-omnibuf`
- `application/connect+omnibuf` (5-byte streaming envelopes, gzip decompression, end-stream JSON)
- `application/connect+x-omnibuf`
- `application/grpc+omnibuf`
- `application/grpc+x-omnibuf`

## Schema Overlay

Both lightweight OmniBuf JSON schemas and Protobuf `FileDescriptorSet` JSON (`buf build -o schema.json`) are supported, sharing the same format as `omnibuf-wireshark`. Inline `Field #0` (`SchemaMeta`) field names are resolved automatically.

## Running Tests

```sh
pytest
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
