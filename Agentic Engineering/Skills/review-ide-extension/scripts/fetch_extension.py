#!/usr/bin/env python3
"""
Fetch a VS Code extension from the VS Code Marketplace or Open VSX.
Usage: python3 fetch_extension.py <publisher.name> [--out DIR] [--registry vscode|open-vsx]

Auto-detects registry if not specified: tries VS Code Marketplace first, falls back to Open VSX.
Outputs the working directory path as the last line of stdout.
"""

import argparse
import json
import pathlib
import sys
import zipfile
import warnings

warnings.filterwarnings("ignore")
import requests

UA = "Mozilla/5.0 VSCodeExtensionReview/1.0"

# --- VS Code Marketplace ---
VSCODE_API = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
VSCODE_HEADERS = {
    "Accept": "application/json;api-version=7.2-preview.1",
    "Content-Type": "application/json",
    "User-Agent": UA,
}
VSCODE_FLAGS = 950  # versions + files + stats + category/tags + asset-uri + shared-accounts

# --- Open VSX ---
OVSX_API = "https://open-vsx.org/api/{namespace}/{name}"


def query_vscode_marketplace(ext_id: str) -> dict:
    body = {
        "filters": [{"criteria": [{"filterType": 7, "value": ext_id}], "pageSize": 1}],
        "flags": VSCODE_FLAGS,
    }
    r = requests.post(VSCODE_API, json=body, headers=VSCODE_HEADERS, timeout=30)
    r.raise_for_status()
    results = r.json().get("results", [])
    if not results or not results[0].get("extensions"):
        return None
    return results[0]["extensions"][0]


def metadata_from_vscode(ext: dict, publisher: str, ext_name: str) -> tuple:
    """Returns (version, vsix_url, metadata_dict)."""
    version_info = ext["versions"][0]
    version = version_info["version"]
    vsix_url = None
    for f in version_info.get("files", []):
        if f.get("assetType") == "Microsoft.VisualStudio.Services.VSIXPackage":
            vsix_url = f["source"]
            break
    if not vsix_url:
        pub = ext["publisher"]["publisherName"]
        vsix_url = (
            f"https://marketplace.visualstudio.com/_apis/public/gallery/publishers/"
            f"{pub}/vsextensions/{ext_name}/{version}/vspackage"
        )
    stats = {s["statisticName"]: s["value"] for s in ext.get("statistics", [])}
    pub_info = ext.get("publisher", {})
    metadata = {
        "extension_id": f"{publisher}.{ext_name}",
        "publisher_name": pub_info.get("publisherName", publisher),
        "publisher_display_name": pub_info.get("displayName", ""),
        "publisher_verified": pub_info.get("flags") == "verified",
        "extension_name": ext.get("extensionName", ext_name),
        "display_name": ext.get("displayName", ""),
        "version": version,
        "last_updated": version_info.get("lastUpdated", ""),
        "short_description": ext.get("shortDescription", ""),
        "tags": ext.get("tags", []),
        "categories": ext.get("categories", []),
        "install_count": int(stats.get("install", 0)),
        "average_rating": round(float(stats.get("averagerating", 0)), 2),
        "rating_count": int(stats.get("ratingcount", 0)),
        "vsix_url": vsix_url,
        "registry": "marketplace.visualstudio.com",
    }
    return version, vsix_url, metadata


def query_open_vsx(namespace: str, name: str) -> dict:
    url = OVSX_API.format(namespace=namespace, name=name)
    r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    data = r.json()
    if data.get("error"):
        return None
    return data


def metadata_from_ovsx(data: dict, publisher: str, ext_name: str) -> tuple:
    """Returns (version, vsix_url, metadata_dict)."""
    version = data.get("version", "0.0.0")
    vsix_url = data.get("files", {}).get("download") or data.get("downloads", {}).get("universal", "")
    published_by = data.get("publishedBy", {})
    metadata = {
        "extension_id": f"{publisher}.{ext_name}",
        "publisher_name": data.get("namespace", publisher),
        "publisher_display_name": published_by.get("fullName") or data.get("namespaceDisplayName", publisher),
        "publisher_verified": data.get("verified", False),
        "extension_name": data.get("name", ext_name),
        "display_name": data.get("displayName", ""),
        "version": version,
        "last_updated": data.get("timestamp", ""),
        "short_description": data.get("description", ""),
        "tags": data.get("tags", []),
        "categories": data.get("categories", []),
        "install_count": int(data.get("downloadCount", 0)),
        "average_rating": round(float(data.get("averageRating") or 0), 2),
        "rating_count": int(data.get("reviewCount", 0)),
        "vsix_url": vsix_url,
        "registry": "open-vsx.org",
        "repository": data.get("repository", ""),
    }
    return version, vsix_url, metadata


def download(url: str, dest: pathlib.Path) -> None:
    r = requests.get(url, headers={"User-Agent": UA}, stream=True, timeout=120)
    r.raise_for_status()
    with open(dest, "wb") as f:
        for chunk in r.iter_content(65536):
            f.write(chunk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("extension_id", help="publisher.name (e.g. ms-python.python)")
    ap.add_argument("--out", default="./extension_reviews")
    ap.add_argument(
        "--registry",
        choices=["vscode", "open-vsx", "auto"],
        default="auto",
        help="Registry to fetch from (default: auto-detect)",
    )
    args = ap.parse_args()

    if "." not in args.extension_id:
        print("[ERROR] Use 'publisher.name' format.", file=sys.stderr)
        sys.exit(1)

    publisher, ext_name = args.extension_id.lower().split(".", 1)
    version = vsix_url = metadata = None

    use_vscode = args.registry in ("vscode", "auto")
    use_ovsx = args.registry in ("open-vsx", "auto")

    if use_vscode:
        print(f"[*] Querying VS Code Marketplace for {args.extension_id} ...", flush=True)
        ext = query_vscode_marketplace(args.extension_id)
        if ext:
            version, vsix_url, metadata = metadata_from_vscode(ext, publisher, ext_name)
            print(f"[*] Found on VS Code Marketplace (v{version}).", flush=True)
        elif args.registry == "vscode":
            print(f"[ERROR] Not found on VS Code Marketplace.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[*] Not on VS Code Marketplace, trying Open VSX ...", flush=True)

    if metadata is None and use_ovsx:
        data = query_open_vsx(publisher, ext_name)
        if data:
            version, vsix_url, metadata = metadata_from_ovsx(data, publisher, ext_name)
            print(f"[*] Found on Open VSX (v{version}).", flush=True)
        else:
            print(f"[ERROR] '{args.extension_id}' not found on any registry.", file=sys.stderr)
            sys.exit(1)

    out_dir = pathlib.Path(args.out).expanduser() / f"{publisher}_{ext_name}_{version}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print(f"[*] Metadata saved ({metadata['registry']}).", flush=True)

    vsix_path = out_dir / f"{ext_name}.vsix"
    print(f"[*] Downloading VSIX v{version} ...", flush=True)
    download(vsix_url, vsix_path)
    print(f"[*] {vsix_path.stat().st_size:,} bytes downloaded.", flush=True)

    vsix_dir = out_dir / "vsix"
    vsix_dir.mkdir(exist_ok=True)
    print("[*] Extracting ...", flush=True)
    with zipfile.ZipFile(vsix_path, "r") as zf:
        zf.extractall(vsix_dir)

    print(f"[+] Working directory: {out_dir}", flush=True)
    print(out_dir)  # machine-readable last line


if __name__ == "__main__":
    main()
