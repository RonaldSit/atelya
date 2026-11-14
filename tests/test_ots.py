"""OpenTimestamps anchoring of the attest v2 head (atelya web3-features-spec W5).

atelya-govern export-digest / anchor-ots / upgrade-ots / verify-ots. Local fakes only:
a fake calendar (records every request) and a fake bitcoind JSON-RPC. Nothing goes to the
public calendars. The official `ots` CLI checks our proofs (interop).

On Python 3.10 the [ots] extra cannot be installed (opentimestamps 0.5.0 needs 3.11): there
every test asserts that the command refuses with a message naming the extra, so the count
is the same on every version. CI sets ATELYA_REQUIRE_OTS=1 on 3.11+ so a missing install
fails instead of taking that path.

This file is identical in atelya and atelya-public. Run: pytest tests/test_ots.py -q
"""

import hashlib
import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


attest = _load("amem_attest")
gov = _load("amem_governance")

try:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import (
        BytesSerializationContext,
        StreamDeserializationContext,
    )
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    HAVE_OTS = True
except ImportError:
    HAVE_OTS = False

if os.environ.get("ATELYA_REQUIRE_OTS") == "1":
    assert HAVE_OTS, "ATELYA_REQUIRE_OTS=1 but opentimestamps is not installed"


def _need(name):
    assert hasattr(gov, name), f"amem_governance.{name} is missing (W5 not implemented)"
    return getattr(gov, name)


def _refuses_without_extra(fn, *a, **k):
    """Python 3.10 (no [ots] extra): the command refuses and names the extra."""
    with pytest.raises(_need("OtsUnavailable")) as ei:
        fn(*a, **k)
    assert "atelya-attest[ots]" in str(ei.value) and "3.11" in str(ei.value), str(ei.value)


# ================================ fakes ============================================
class FakeCalendar:
    """POST /digest answers a pending timestamp; GET /timestamp/<hex> a Bitcoin one once
    confirmed. Every request is recorded (method, path, body)."""

    def __init__(self):
        self.requests, self.confirmed, self.height = [], False, 840000
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                outer.requests.append(("POST", self.path, body))
                if self.path != "/digest":
                    return self._send(404, b"unknown")
                self._send(200, outer.pending(body))

            def do_GET(self):
                outer.requests.append(("GET", self.path, b""))
                if not self.path.startswith("/timestamp/") or not outer.confirmed:
                    return self._send(404, b"Pending confirmation in Bitcoin blockchain")
                commitment = bytes.fromhex(self.path[len("/timestamp/") :])
                self._send(200, outer.bitcoin(commitment))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def commitment(self, digest):
        return hashlib.sha256(digest + b"\x01" * 16).digest()

    def pending(self, digest):
        ts = Timestamp(digest)
        ts.ops.add(OpAppend(b"\x01" * 16)).ops.add(OpSHA256()).attestations.add(
            PendingAttestation(self.url)
        )
        ctx = BytesSerializationContext()
        ts.serialize(ctx)
        return ctx.getbytes()

    def merkle_root(self, commitment):
        return hashlib.sha256(commitment).digest()

    def bitcoin(self, commitment):
        ts = Timestamp(commitment)
        ts.ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(self.height))
        ctx = BytesSerializationContext()
        ts.serialize(ctx)
        return ctx.getbytes()

    def close(self):
        self.server.shutdown()


class FakeBitcoind:
    """getblockcount / getblockhash / getblockheader for one block whose merkle root we set."""

    def __init__(self, height, merkle_root, ntime=1790000000):
        from bitcoin.core import CBlockHeader

        self.height = height
        self.header = CBlockHeader(
            nVersion=1,
            hashPrevBlock=b"\x00" * 32,
            hashMerkleRoot=merkle_root,
            nTime=ntime,
            nBits=0x207FFFFF,
        )
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                m, params = req.get("method"), req.get("params") or []
                if m == "getblockcount":
                    res, err = outer.height + 10, None
                elif m == "getblockhash":
                    res, err = (
                        (outer.header.GetHash()[::-1].hex(), None)
                        if params[0] == outer.height
                        else (
                            None,
                            {"code": -8, "message": "Block height out of range"},
                        )
                    )
                elif m == "getblockheader":
                    res, err = outer.header.serialize().hex(), None
                else:
                    res, err = None, {"code": -32601, "message": "Method not found"}
                body = json.dumps({"result": res, "error": err, "id": req.get("id")}).encode()
                self.send_response(200 if err is None else 500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://user:pass@127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture()
def calendar():
    if not HAVE_OTS:
        yield None
        return
    c = FakeCalendar()
    yield c
    c.close()


def _chain(tmp_path, n=3):
    p = os.path.join(str(tmp_path), "user.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        for i in range(n):
            f.write(
                json.dumps(
                    {
                        "op": "add",
                        "id": f"a{i:011x}",
                        "text": f"neutral ots note {i}",
                        "key": None,
                        "ts": f"1970-01-01T00:00:0{i}.000000Z",
                        "v": 2,
                    }
                )
                + "\n"
            )
    gov.attest_v2(p)
    return p, p + ".attest.jsonl"


def _head(chain_path):
    return attest.chain_head_v2(gov._read_chain(chain_path))


def _proof(path):
    with open(path, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def _cli(*argv, env=None):
    e = {k: v for k, v in os.environ.items() if k not in ("AMEM_PRIVATE", "ATELYA_OTS_CALENDARS")}
    e.update(env or {})
    return subprocess.run(
        [sys.executable, os.path.join(_ROOT, "amem_governance.py"), *argv],
        capture_output=True,
        text=True,
        timeout=120,
        env=e,
    )


# ================================ export-digest ====================================
def test_export_digest_writes_the_head_and_its_last_seq(tmp_path):
    _p, ch = _chain(tmp_path)
    out = _need("export_digest")(ch)
    text = open(out["digest_file"], encoding="utf-8").read().splitlines()
    assert text[0] == _head(ch) and len(bytes.fromhex(text[0])) == 32
    assert "# last_seq 2" in text and out["last_seq"] == 2
    r = _cli("export-digest", ch)
    assert r.returncode == 0 and _head(ch) in r.stdout and "last seq 2" in r.stdout, (
        r.stdout + r.stderr
    )


def test_export_digest_refuses_a_v1_chain(tmp_path):
    p = os.path.join(str(tmp_path), "user.jsonl")
    with open(p, "w") as f:
        f.write(json.dumps({"op": "add", "id": "a1", "text": "neutral"}) + "\n")
    assert _cli("attest", p).returncode == 0
    r = _cli("export-digest", p + ".attest.jsonl")
    assert r.returncode == 1 and "v2" in r.stderr, r.stdout + r.stderr


# ================================ anchor-ots =======================================
def test_anchor_sends_only_the_32_byte_digest(tmp_path, calendar):
    _p, ch = _chain(tmp_path)
    if not HAVE_OTS:
        return _refuses_without_extra(_need("anchor_ots"), ch, calendars=["http://127.0.0.1:9/"])
    second = FakeCalendar()
    try:
        _need("anchor_ots")(ch, calendars=[calendar.url, second.url])
    finally:
        second.close()
    head = bytes.fromhex(_head(ch))
    for c in (calendar, second):
        assert c.requests == [("POST", "/digest", head)], c.requests


def test_anchor_writes_a_proof_of_the_head(tmp_path, calendar):
    _p, ch = _chain(tmp_path)
    if not HAVE_OTS:
        return _refuses_without_extra(_need("anchor_ots"), ch, calendars=["http://127.0.0.1:9/"])
    out = _need("anchor_ots")(ch, calendars=[calendar.url])
    dtf = _proof(out["proof"])
    assert out["proof"] == ch + ".ots"
    assert isinstance(dtf.file_hash_op, OpSHA256) and dtf.file_digest.hex() == _head(ch)
    atts = [a for _m, a in dtf.timestamp.all_attestations()]
    assert atts == [PendingAttestation(calendar.url)], atts


def test_every_anchor_states_its_scope(tmp_path, calendar):
    _p, ch = _chain(tmp_path)
    if not HAVE_OTS:
        return _refuses_without_extra(_need("anchor_ots"), ch, calendars=["http://127.0.0.1:9/"])
    r = _cli("anchor-ots", ch, "--calendar", calendar.url)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "last seq 2" in r.stdout and "not covered until the next anchor" in r.stdout, r.stdout
    note = json.load(open(ch + ".ots.note.json", encoding="utf-8"))
    assert (
        note["last_seq"] == 2
        and note["head"] == _head(ch)
        and "not covered until the next anchor" in note["scope"]
    )


def test_anchor_from_a_digest_file(tmp_path, calendar):
    _p, ch = _chain(tmp_path)
    df = _need("export_digest")(ch)["digest_file"]
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("anchor_ots"), None, digest_file=df, calendars=["http://127.0.0.1:9/"]
        )
    out = _need("anchor_ots")(None, digest_file=df, calendars=[calendar.url])
    assert out["proof"] == df + ".ots" and _proof(out["proof"]).file_digest.hex() == _head(ch)
    assert json.load(open(out["proof"] + ".note.json"))["last_seq"] == 2


def test_anchor_fails_when_no_calendar_answers(tmp_path):
    _p, ch = _chain(tmp_path)
    if not HAVE_OTS:
        return _refuses_without_extra(_need("anchor_ots"), ch, calendars=["http://127.0.0.1:9/"])
    with pytest.raises(_need("OtsError"), match="no calendar"):
        _need("anchor_ots")(ch, calendars=["http://127.0.0.1:9/"], timeout=2)
    assert not os.path.exists(ch + ".ots")


@pytest.mark.parametrize("cmd", ["anchor-ots", "upgrade-ots"])
def test_private_mode_refuses_the_network_and_points_to_export_digest(tmp_path, calendar, cmd):
    _p, ch = _chain(tmp_path)
    target = ch
    if cmd == "upgrade-ots":
        if HAVE_OTS:
            target = _need("anchor_ots")(ch, calendars=[calendar.url])["proof"]
            calendar.requests.clear()
        else:
            target = ch + ".ots"
            open(target, "wb").close()
    url = calendar.url if calendar else "http://127.0.0.1:9/"
    r = _cli(cmd, target, "--calendar", url, env={"AMEM_PRIVATE": "1"})
    assert r.returncode == 1 and "export-digest" in r.stderr and "--allow-network" in r.stderr, (
        r.stderr
    )
    if calendar:
        assert calendar.requests == []
        r = _cli(cmd, target, "--calendar", url, "--allow-network", env={"AMEM_PRIVATE": "1"})
        assert r.returncode == 0, r.stdout + r.stderr


# ================================ upgrade-ots, verify-ots ==========================
def _anchored(tmp_path, calendar):
    _p, ch = _chain(tmp_path)
    proof = _need("anchor_ots")(ch, calendars=[calendar.url])["proof"]
    return ch, proof


def test_upgrade_fetches_the_bitcoin_attestation(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(_need("upgrade_ots"), str(tmp_path / "x.ots"))
    ch, proof = _anchored(tmp_path, calendar)
    calendar.requests.clear()
    r0 = _need("upgrade_ots")(proof, calendars=[calendar.url])
    assert r0["changed"] is False and r0["bitcoin_heights"] == []
    calendar.confirmed = True
    r1 = _need("upgrade_ots")(proof, calendars=[calendar.url])
    assert r1["changed"] is True and r1["bitcoin_heights"] == [calendar.height], r1
    c = calendar.commitment(bytes.fromhex(_head(ch))).hex()
    assert all(rq == ("GET", f"/timestamp/{c}", b"") for rq in calendar.requests), calendar.requests


def test_upgrade_contacts_no_calendar_outside_the_whitelist(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(_need("upgrade_ots"), str(tmp_path / "x.ots"))
    _ch, proof = _anchored(tmp_path, calendar)
    calendar.requests.clear()
    r = _need("upgrade_ots")(proof, calendars=[])  # the fake calendar is not whitelisted now
    assert r["changed"] is False and r["skipped"] == [calendar.url] and calendar.requests == [], r


def test_verify_reports_pending_before_bitcoin(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    ch, proof = _anchored(tmp_path, calendar)
    r = _cli("verify-ots", proof, ch)
    assert r.returncode == 3 and "pending" in r.stdout.lower(), r.stdout + r.stderr


def _confirmed(tmp_path, calendar):
    ch, proof = _anchored(tmp_path, calendar)
    calendar.confirmed = True
    _need("upgrade_ots")(proof, calendars=[calendar.url])
    root = calendar.merkle_root(calendar.commitment(bytes.fromhex(_head(ch))))
    return ch, proof, root


def test_verify_against_bitcoind(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    ch, proof, root = _confirmed(tmp_path, calendar)
    node = FakeBitcoind(calendar.height, root)
    try:
        r = _cli("verify-ots", proof, ch, "--bitcoin-node", node.url)
    finally:
        node.close()
    assert r.returncode == 0 and "VERIFIED" in r.stdout and str(calendar.height) in r.stdout, (
        r.stdout + r.stderr
    )
    wrong = FakeBitcoind(calendar.height, b"\x07" * 32)
    try:
        r = _cli("verify-ots", proof, ch, "--bitcoin-node", wrong.url)
    finally:
        wrong.close()
    assert r.returncode == 1 and "merkle" in (r.stdout + r.stderr).lower(), r.stdout + r.stderr


def test_verify_refuses_a_proof_of_another_chain(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    _ch, proof = _anchored(tmp_path / "one", calendar)
    _p2, other = _chain(tmp_path / "two", n=4)
    r = _cli("verify-ots", proof, other)
    assert r.returncode == 1 and "does not commit" in r.stderr, r.stdout + r.stderr


def test_a_proof_still_covers_its_prefix_after_the_chain_grew(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    ch, proof = _anchored(tmp_path, calendar)
    oplog = ch[: -len(".attest.jsonl")]
    with open(oplog, "a") as f:
        f.write(
            json.dumps(
                {"op": "forget", "id": "a00000000000", "ts": "1970-01-01T00:00:09.000000Z", "v": 2}
            )
            + "\n"
        )
    gov.attest_v2(oplog)
    r = _need("verify_ots")(proof, ch)
    assert r["status"] == "pending" and r["covered_last_seq"] == 2 and r["chain_last_seq"] == 3, r


def test_verify_from_a_digest_file(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    ch, proof = _anchored(tmp_path, calendar)
    df = _need("export_digest")(ch)["digest_file"]
    assert _need("verify_ots")(proof, None, digest_file=df)["status"] == "pending"


# ================================ interop with the official client ================
def _ots_bin():
    exe = shutil.which("ots", path=os.path.dirname(sys.executable)) or shutil.which("ots")
    assert exe, "the official ots CLI (opentimestamps-client) is not installed"
    return exe


def test_the_official_ots_client_verifies_our_proof(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    ch, proof, root = _confirmed(tmp_path, calendar)
    node = FakeBitcoind(calendar.height, root)
    try:
        r = subprocess.run(
            [
                _ots_bin(),
                "--no-cache",
                "--no-default-whitelist",
                "--bitcoin-node",
                node.url,
                "verify",
                "-d",
                _head(ch),
                proof,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        node.close()
    out = r.stdout + r.stderr
    assert r.returncode == 0 and f"Bitcoin block {calendar.height} attests" in out, out
    info = subprocess.run([_ots_bin(), "info", proof], capture_output=True, text=True, timeout=60)
    assert info.returncode == 0 and _head(ch) in info.stdout, info.stdout + info.stderr


def test_the_official_ots_client_reads_a_pending_proof(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    ch, proof = _anchored(tmp_path, calendar)
    r = subprocess.run(
        [
            _ots_bin(),
            "--no-cache",
            "--no-default-whitelist",
            "-l",
            calendar.url,
            "--no-bitcoin",
            "verify",
            "-d",
            _head(ch),
            proof,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert "Pending confirmation" in (r.stdout + r.stderr), r.stdout + r.stderr


def test_without_the_extra_the_commands_name_it(monkeypatch, tmp_path):
    import builtins

    real = builtins.__import__

    def no_ots(name, *a, **k):
        if name.startswith("opentimestamps") or name.startswith("bitcoin"):
            raise ImportError("simulated: no [ots] extra")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_ots)
    _refuses_without_extra(
        _need("anchor_ots"), str(tmp_path / "c"), calendars=["http://127.0.0.1:9/"]
    )


def test_a_malformed_digest_file_is_refused(tmp_path):
    bad = str(tmp_path / "digest.txt")
    with open(bad, "w") as f:
        f.write("abcd\n# last_seq 2\n")
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("anchor_ots"), None, digest_file=bad, calendars=["http://127.0.0.1:9/"]
        )
    with pytest.raises(_need("OtsError"), match="32-byte"):
        _need("anchor_ots")(None, digest_file=bad, calendars=["http://127.0.0.1:9/"])


def test_the_calendars_can_come_from_the_environment(tmp_path, calendar):
    _p, ch = _chain(tmp_path)
    url = calendar.url if calendar else "http://127.0.0.1:9/"
    r = _cli("anchor-ots", ch, env={"ATELYA_OTS_CALENDARS": url})
    if not HAVE_OTS:
        assert r.returncode == 1 and "atelya-attest[ots]" in r.stderr, r.stderr
        return
    assert r.returncode == 0 and calendar.requests == [
        ("POST", "/digest", bytes.fromhex(_head(ch)))
    ], (
        r.stdout + r.stderr,
        calendar.requests,
    )


def test_verify_refuses_a_digest_file_of_another_head(tmp_path, calendar):
    if not HAVE_OTS:
        return _refuses_without_extra(
            _need("verify_ots"), str(tmp_path / "x.ots"), str(tmp_path / "c")
        )
    _ch, proof = _anchored(tmp_path, calendar)
    other = str(tmp_path / "other.txt")
    with open(other, "w") as f:
        f.write("11" * 32 + "\n# last_seq 2\n")
    with pytest.raises(_need("OtsError"), match="does not commit"):
        _need("verify_ots")(proof, None, digest_file=other)
