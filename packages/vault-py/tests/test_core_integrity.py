"""The core integrity pin (gate G5, "a core changed on disk that reports the pinned version").

Three layers:

1. The pin file against the repository: ``scripts/core-integrity.py check`` (offline) compares ``_core_pin.py`` with
   ``package.json`` and ``package-lock.json``, and against the installed core when there is one. CI also runs it with
   ``--fetch``, which downloads the published tarballs and recomputes every digest; that needs the network and is not
   a unit test.
2. The Python side of the protocol, against a scripted child: what a response must report, and what is refused.
3. The real child over a copy of the installed core: a copy is accepted, every kind of change is refused before the
   core runs, and the child's digest is the reference function's. The wider run (every platform addon, NODE_PATH)
   is ``tests/bridge_qualification.py --section failclosed``.

Data is synthetic. A copy of the core is a few megabytes; nothing is modified in place.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from redact_secret_vault import NodeCoreBridge, VaultServerError, VaultServerErrorCode
from redact_secret_vault import core_client as core_client_module
from redact_secret_vault._core_pin import CORE_PACKAGES
from redact_secret_vault.core_client import PINNED_CORE_INTEGRITY, PINNED_CORE_VERSION

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "core-integrity.py"
REAL_NODE_MODULES = REPO / "node_modules"
HAS_REAL_CORE = (REAL_NODE_MODULES / "@redact-secret" / "core" / "package.json").is_file()
needs_core = pytest.mark.skipif(
    shutil.which("node") is None or not HAS_REAL_CORE, reason="needs node and `npm ci` at the repository root"
)
needs_repo = pytest.mark.skipif(
    not (SCRIPT.is_file() and (REPO / "package-lock.json").is_file()), reason="needs the repository's scripts"
)
REFUSED = "CORE_INTEGRITY_MISMATCH"


def _reference():
    spec = importlib.util.spec_from_file_location("core_integrity_reference", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- 1. The pin file against the repository ---------------------------------------


def test_the_pin_names_every_package_at_the_pinned_version() -> None:
    assert set(CORE_PACKAGES) == set(PINNED_CORE_INTEGRITY)
    assert "@redact-secret/core" in CORE_PACKAGES and "@redact-secret/wasm" in CORE_PACKAGES
    assert sum(name.startswith("@redact-secret/node-") for name in CORE_PACKAGES) == 8
    assert {pin["version"] for pin in CORE_PACKAGES.values()} == {PINNED_CORE_VERSION}
    assert all(len(digest) == 64 and digest == digest.lower() for digest in PINNED_CORE_INTEGRITY.values())
    assert len(set(PINNED_CORE_INTEGRITY.values())) == len(PINNED_CORE_INTEGRITY)


@needs_repo
def test_the_pin_agrees_with_package_json_and_package_lock() -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "check"], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    assert "10 packages" in done.stdout


@needs_repo
@needs_core
def test_the_installed_core_is_the_pinned_one() -> None:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "check", "--installed", str(REAL_NODE_MODULES)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr


@needs_repo
def test_the_check_notices_a_pin_that_drifted_from_the_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reference = _reference()
    pin = json.loads(json.dumps({name: dict(entry) for name, entry in CORE_PACKAGES.items()}))
    entries = reference.lock_entries()
    assert reference.check_offline(pin, entries) == []
    pin["@redact-secret/core"]["tarball"] = "sha512-" + "A" * 86 + "=="
    assert any("tarball integrity differs" in p for p in reference.check_offline(pin, entries))
    pin["@redact-secret/core"]["version"] = "0.0.0"
    assert any("PINNED_CORE_VERSION" in p for p in reference.check_offline(pin, entries))
    del pin["@redact-secret/wasm"]
    assert any("the pin names" in p for p in reference.check_offline(pin, entries))


def test_the_digest_is_a_function_of_names_sizes_and_contents(tmp_path: Path) -> None:
    reference = _reference()
    one = {"a.js": b"x", "dir/b.js": b"yy"}
    assert reference.tree_digest_of_files(one) == reference.tree_digest_of_files(dict(reversed(one.items())))
    assert reference.tree_digest_of_files(one) != reference.tree_digest_of_files({**one, "c": b""})
    assert reference.tree_digest_of_files(one) != reference.tree_digest_of_files({"a.js": b"x", "dir/c.js": b"yy"})
    assert reference.tree_digest_of_files(one) != reference.tree_digest_of_files({"a.js": b"x", "dir/b.js": b"yz"})
    # Sorted by the UTF-8 bytes of the path, not by code point: U+FF5E (EF BD 9E) sorts before U+1F600 (F0 9F ...)
    # in UTF-8, and after it in UTF-16.
    files = {"\U0001f600": b"1", "～": b"2"}
    lines = "".join(
        f"{__import__('hashlib').sha256(files[name]).hexdigest()} 1 {name}\n"
        for name in sorted(files, key=lambda n: n.encode())
    )
    expected = __import__("hashlib").sha256(lines.encode()).hexdigest()
    assert reference.tree_digest_of_files(files) == expected
    # A directory with a symbolic link has no digest.
    (tmp_path / "real").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with pytest.raises(SystemExit):
        reference.tree_digest_of_dir(tmp_path)


# -- 2. The Python side against a scripted child -------------------------------------


class _Popen:
    instances: list[_Popen] = []
    script: list = []

    def __init__(self, args, **_kwargs) -> None:
        self.args = args
        self.pid = 91000 + len(_Popen.instances)
        self.returncode = None
        self.requests: list[dict] = []
        self.stdin = self.stdout = self
        self._pending: list[bytes] = []
        _Popen.instances.append(self)

    def write(self, data: bytes) -> int:
        request = json.loads(data)
        self.requests.append(request)
        action = _Popen.script.pop(0)
        self._pending.append(json.dumps(action(request)).encode() + b"\n")
        return len(data)

    def flush(self) -> None:
        pass

    def readline(self, _limit: int = -1) -> bytes:
        return self._pending.pop(0) if self._pending else b""

    def close(self) -> None:
        pass

    def poll(self):
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch):
    _Popen.instances = []
    _Popen.script = []
    monkeypatch.setattr(core_client_module.subprocess, "Popen", _Popen)

    def install(*actions):
        _Popen.script = list(actions)
        return _Popen.instances

    return install


def _response(request: dict, *, integrity, artifact: str = "addon") -> dict:
    return {
        "id": request["id"],
        "findings": [],
        "coreVersion": PINNED_CORE_VERSION,
        "artifact": artifact,
        "piiActivation": None,
        "integrity": integrity,
    }


def _verified(addon: bool = True) -> dict[str, str]:
    names = ["@redact-secret/core", "@redact-secret/wasm"] + (["@redact-secret/node-darwin-arm64"] if addon else [])
    return {name: PINNED_CORE_INTEGRITY[name] for name in names}


def _bridge(**kwargs) -> NodeCoreBridge:
    return NodeCoreBridge(node_executable="node-fake-synthetic", **kwargs)


def _refusal(bridge: NodeCoreBridge) -> VaultServerError:
    with pytest.raises(VaultServerError) as excinfo:
        bridge.scan("x")
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.__cause__ is None
    return excinfo.value


def test_the_first_request_of_a_process_carries_the_pin_and_later_ones_do_not(scripted) -> None:
    processes = scripted(
        lambda r: _response(r, integrity=_verified()),
        lambda r: _response(r, integrity=None),
        lambda r: _response(r, integrity=_verified()),
    )
    bridge = _bridge(max_scans_per_process=2)
    for _ in range(3):
        bridge.scan("x")
    assert processes[0].requests[0]["integrity"] == dict(PINNED_CORE_INTEGRITY)
    assert "integrity" not in processes[0].requests[1]
    assert processes[1].requests[0]["integrity"] == dict(PINNED_CORE_INTEGRITY)


def test_an_opted_out_bridge_sends_no_pin_and_accepts_no_digests(scripted) -> None:
    processes = scripted(lambda r: _response(r, integrity=None), lambda r: _response(r, integrity=_verified()))
    bridge = _bridge(expected_core_integrity=None)
    bridge.scan("x")
    assert "integrity" not in processes[0].requests[0]
    assert _refusal(_bridge(expected_core_integrity=None)).core_code == "BRIDGE_BAD_OUTPUT"


@pytest.mark.parametrize(
    ("integrity", "artifact", "expected"),
    [
        (None, "addon", "BRIDGE_BAD_OUTPUT"),  # a bridge script that does not verify
        ({}, "addon", "BRIDGE_BAD_OUTPUT"),
        ([], "addon", "BRIDGE_BAD_OUTPUT"),
        ("verified", "addon", "BRIDGE_BAD_OUTPUT"),
        ({"@redact-secret/core": 5}, "addon", "BRIDGE_BAD_OUTPUT"),
        ({**_verified(), "@redact-secret/other": "0" * 64}, "addon", "BRIDGE_BAD_OUTPUT"),  # a name that was not pinned
        ({**_verified(), "@redact-secret/core": "0" * 64}, "addon", REFUSED),  # another digest
        ({k: v for k, v in _verified().items() if k != "@redact-secret/wasm"}, "addon", REFUSED),
        ({k: v for k, v in _verified().items() if k != "@redact-secret/core"}, "addon", REFUSED),
        (_verified(addon=False), "addon", REFUSED),  # an addon that nobody verified
    ],
)
def test_a_response_that_does_not_report_the_pinned_digests_is_refused(scripted, integrity, artifact, expected) -> None:
    scripted(lambda r: _response(r, integrity=integrity, artifact=artifact))
    error = _refusal(_bridge())
    assert error.core_code == expected
    assert "0000" not in str(error)


@pytest.mark.parametrize("artifact", ["addon", "wasm"])
def test_the_pinned_digests_with_the_artifact_that_was_verified_are_accepted(scripted, artifact) -> None:
    scripted(lambda r: _response(r, integrity=_verified(addon=artifact == "addon"), artifact=artifact))
    assert _bridge().scan("x").artifact == artifact


def test_a_later_response_that_reports_digests_is_refused(scripted) -> None:
    scripted(lambda r: _response(r, integrity=_verified()), lambda r: _response(r, integrity=_verified()))
    bridge = _bridge()
    bridge.scan("x")
    assert _refusal(bridge).core_code == "BRIDGE_BAD_OUTPUT"


def test_a_refusal_by_the_child_is_a_fixed_core_failure(scripted) -> None:
    error_frame = {"message": "core integrity check failed", "code": REFUSED}
    processes = scripted(lambda r: {"id": r["id"], "error": error_frame}, lambda r: _response(r, integrity=_verified()))
    bridge = _bridge()
    error = _refusal(bridge)
    assert error.core_code == REFUSED and str(error) == f"CORE_FAILURE core_code={REFUSED}"
    assert processes[0].returncode == -9  # discarded; the next scan starts a new process
    bridge.scan("x")


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"@redact-secret/core": "0" * 64},  # no wasm
        {"@redact-secret/core": "0" * 64, "@redact-secret/wasm": "g" * 64},
        {"@redact-secret/core": "0" * 64, "@redact-secret/wasm": "A" * 64},
        {"@redact-secret/core": "0" * 63, "@redact-secret/wasm": "0" * 64},
        {"@redact-secret/core": "0" * 64, "@redact-secret/wasm": "0" * 64, "evil/pkg": "0" * 64},
        {"@redact-secret/core": "0" * 64, "@redact-secret/wasm": "0" * 64, "@redact-secret/../x": "0" * 64},
        "x",
        5,
    ],
)
def test_a_malformed_pin_is_an_invalid_argument(value) -> None:
    with pytest.raises(VaultServerError) as excinfo:
        NodeCoreBridge(node_executable="node-fake-synthetic", expected_core_integrity=value)
    assert excinfo.value.code == VaultServerErrorCode.INVALID_ARGUMENT


# -- 3. The real child over a copy of the installed core ---------------------------------


def _copy(target: Path, *, addon: bool = True) -> Path:
    scope = target / "node_modules" / "@redact-secret"
    scope.mkdir(parents=True)
    for source in sorted((REAL_NODE_MODULES / "@redact-secret").iterdir()):
        if source.name in ("core", "wasm") or (addon and source.name.startswith("node-")):
            shutil.copytree(source, scope / source.name, symlinks=True)
    return target / "node_modules"


def _flip(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))


def _scan(node_modules: Path, **kwargs):
    with NodeCoreBridge(node_modules=str(node_modules), timeout_s=60.0, **kwargs) as bridge:
        return bridge.scan("deploy ghp_SYNTHETICxREVOKEDxTESTx0000000000000 now")


@needs_core
def test_a_copy_of_the_installed_core_is_accepted_with_its_addon_and_with_the_fallback(tmp_path: Path) -> None:
    with_addon = _scan(_copy(tmp_path / "a"))
    assert with_addon.artifact == "addon" and len(with_addon.findings) == 1
    fallback = _scan(_copy(tmp_path / "b", addon=False))
    assert fallback.artifact == "wasm" and len(fallback.findings) == 1


def _core(node_modules: Path) -> Path:
    return node_modules / "@redact-secret" / "core"


def _tamper_core_byte(nm: Path) -> None:
    _flip(_core(nm) / "dist" / "index.js")


def _tamper_core_extra(nm: Path) -> None:
    (_core(nm) / "dist" / "extra.js").write_text("export {};\n")


def _tamper_core_removed(nm: Path) -> None:
    (_core(nm) / "dist" / "formatters.d.ts").unlink()


def _tamper_core_link(nm: Path) -> None:
    link = _core(nm) / "dist" / "version.d.ts"
    link.unlink()
    link.symlink_to(_core(nm) / "dist" / "version.js")


def _tamper_wasm(nm: Path) -> None:
    _flip(next((nm / "@redact-secret" / "wasm").glob("*.wasm")))


def _tamper_wasm_missing(nm: Path) -> None:
    shutil.rmtree(nm / "@redact-secret" / "wasm")


def _tamper_addon(nm: Path) -> None:
    _flip(next((nm / "@redact-secret").glob("node-*/*.node")))


@needs_core
@pytest.mark.parametrize(
    "tamper",
    [
        _tamper_core_byte,
        _tamper_core_extra,
        _tamper_core_removed,
        _tamper_core_link,
        _tamper_wasm,
        _tamper_wasm_missing,
        _tamper_addon,
    ],
)
def test_every_kind_of_change_is_refused_with_a_fixed_message(tmp_path: Path, tamper) -> None:
    nm = _copy(tmp_path)
    tamper(nm)
    with pytest.raises(VaultServerError) as excinfo:
        _scan(nm)
    assert excinfo.value.code == VaultServerErrorCode.CORE_FAILURE
    assert excinfo.value.core_code == REFUSED
    assert str(excinfo.value) == f"CORE_FAILURE core_code={REFUSED}"
    assert str(tmp_path) not in repr(excinfo.value) and excinfo.value.__cause__ is None


@needs_core
def test_a_replacement_core_that_reports_the_pinned_version_never_runs(tmp_path: Path) -> None:
    ran = tmp_path / "ran-synthetic"
    package = tmp_path / "node_modules" / "@redact-secret" / "core"
    package.mkdir(parents=True)
    manifest = {"name": "@redact-secret/core", "type": "module", "main": "index.js"}
    (package / "package.json").write_text(json.dumps(manifest))
    (package / "index.js").write_text(
        f"""import {{ writeFileSync }} from "node:fs";
writeFileSync({json.dumps(str(ran))}, "imported");
export const VERSION = {json.dumps(PINNED_CORE_VERSION)};
export async function initialize() {{}}
export function artifact() {{ return "addon"; }}
export function scan() {{ return []; }}
"""
    )
    with pytest.raises(VaultServerError) as excinfo:
        _scan(tmp_path / "node_modules")
    assert excinfo.value.core_code == REFUSED
    assert not ran.exists(), "the replacement core's code ran before it was verified"
    # The same fake with the pin switched off is what the version check alone used to accept.
    outcome = _scan(tmp_path / "node_modules", expected_core_integrity=None)
    assert outcome.findings == () and ran.exists()


@needs_core
@needs_repo
def test_the_childs_digest_is_the_reference_digest(tmp_path: Path) -> None:
    """Pins computed by the reference function for a modified copy are accepted by the child: the two agree."""
    reference = _reference()
    nm = _copy(tmp_path)
    _tamper_core_byte(nm)
    pins = {
        f"@redact-secret/{path.name}": reference.tree_digest_of_dir(path)
        for path in sorted((nm / "@redact-secret").iterdir())
    }
    assert _scan(nm, expected_core_integrity=pins).artifact == "addon"
    pins["@redact-secret/core"] = PINNED_CORE_INTEGRITY["@redact-secret/core"]
    with pytest.raises(VaultServerError) as excinfo:
        _scan(nm, expected_core_integrity=pins)
    assert excinfo.value.core_code == REFUSED
