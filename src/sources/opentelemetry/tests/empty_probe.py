"""Public synthetic first-hop controls; no backend/persistence claim."""
import argparse
import json
import socket
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler


def probe(base):
    opener = build_opener(ProxyHandler({}))
    observations = []
    shapes = [("default", b""), ("empty-resource", bytes.fromhex("0a00")),
        ("empty-scope", bytes.fromhex("0a021200"))]
    cases = [(signal, shape, payload, "application/x-protobuf")
        for signal in ["traces", "logs", "metrics"] for shape, payload in shapes]
    for signal, resources, scopes in [("traces", "resourceSpans", "scopeSpans"),
        ("logs", "resourceLogs", "scopeLogs"), ("metrics", "resourceMetrics", "scopeMetrics")]:
        for shape, payload in [("json-default", {}), ("json-empty-list", {resources: []}),
            ("json-empty-resource", {resources: [{}]}), ("json-empty-scope", {resources: [{scopes: [{}]}]})]:
            cases.append((signal, shape, json.dumps(payload).encode(), "application/json"))
    cases += [("traces", "repeat-default", b"", "application/x-protobuf"),
        ("traces", "malformed-protobuf", bytes.fromhex("80"), "application/x-protobuf"),
        ("traces", "json-incomplete-body", b"", "application/json"),
        ("traces", "json-malformed", b"{", "application/json"),
        ("traces", "json-named-enum", b'{"resourceSpans":[{"scopeSpans":[{"spans":[{"kind":"SPAN_KIND_INTERNAL"}]}]}]}', "application/json"),
        ("traces", "json-unknown-field", b'{"futureEnvelope":{"kind":"IGNORED","traceId":"not-hex"}}', "application/json"),
        ("traces", "json-proto-alias-is-unknown", b'{"resource_spans":[{"scopeSpans":[{"spans":[{}]}]}]}', "application/json")]
    for signal, shape, payload, content in cases:
        request = Request(base + "/v1/" + signal, data=payload,
            headers={"Content-Type": content}, method="POST")
        try:
            response = opener.open(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(65537)
            if len(body) > 65536:
                raise RuntimeError("response exceeded probe bound")
            observations.append({"signal": signal, "shape": shape, "request_content_type": content,
                "request_hex": payload.hex(), "status": response.status,
                "response_content_type": response.headers.get("Content-Type"), "response_hex": body.hex()})
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base")
    parser.add_argument("--expect", choices=["baseline", "fixed"], required=True)
    args = parser.parse_args()
    host, port = args.base.removeprefix("http://").rsplit(":", 1)
    for attempt in range(40):
        try:
            with socket.create_connection((host, int(port)), timeout=0.5):
                break
        except OSError:
            if attempt == 39:
                raise
            time.sleep(0.25)
    rows = probe(args.base)
    result = {"scope": "synthetic HTTP source admission only", "mode": args.expect,
        "observations": rows, "backend_persistence": "not exercised"}
    print(json.dumps(result, indent=2), flush=True)
    defaults = [r for r in rows if r["shape"] in ["default", "repeat-default"]]
    if args.expect == "baseline":
        assert all(r["status"] == 400 for r in defaults), "baseline rejection was not reproduced"
        print("BASELINE_REPRODUCED: valid default protobuf exports rejected with400")
    else:
        negatives = {"malformed-protobuf", "json-incomplete-body", "json-malformed", "json-named-enum"}
        positives = [r for r in rows if r["shape"] not in negatives]
        assert all(r["status"] == 200 for r in positives), "empty export support failed"
        for row in positives:
            if row["request_content_type"] == "application/x-protobuf":
                assert row["response_content_type"] == "application/x-protobuf" and row["response_hex"] == ""
            else:
                assert row["response_content_type"].startswith("application/json")
                assert json.loads(bytes.fromhex(row["response_hex"])) == {}
        assert all(r["status"] == 400 for r in rows if r["shape"] in negatives)
        print("FIXED_EMPTY_CONTROLS_PASS: canonical zero-record responses, no persistence claim")
    assert next(r for r in rows if r["shape"] == "malformed-protobuf")["status"] == 400


if __name__ == "__main__":
    main()
