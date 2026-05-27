#!/usr/bin/env python3
"""
Fetch a Chrome or Firefox browser extension for security review.
Usage: python3 fetch_browser_extension.py <url-or-id> [--out DIR] [--browser chrome|firefox]

Accepts:
  Chrome Web Store URL: https://chromewebstore.google.com/detail/name/id
  Firefox AMO URL:      https://addons.mozilla.org/en-US/firefox/addon/slug/
  Chrome extension ID:  32-char lowercase string
  Firefox slug:         use with --browser firefox

Outputs the working directory path as the last line of stdout.
"""

import argparse
import json
import pathlib
import re
import sys
import zipfile
import warnings

warnings.filterwarnings("ignore")
import requests

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

CHROME_CRX_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&os=mac&arch=x64&prod=chromiumcrx"
    "&prodversion=120.0.0.0&acceptformat=crx2,crx3"
    "&x=id%3D{id}%26uc"
)
CHROME_STORE_URL = "https://chromewebstore.google.com/detail/{id}"
AMO_API_V4 = "https://addons.mozilla.org/api/v4/addons/addon/{slug}/"
CHROME_ID_RE = re.compile(r"^[a-z]{32}$")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_browser_and_id(value: str, browser_hint: str) -> tuple:
    """Returns (browser, id_or_slug)."""
    if browser_hint:
        # Strip URL to bare ID/slug
        if "chromewebstore.google.com" in value or "chrome.google.com" in value:
            m = re.search(r"/([a-z]{32})(?:[/?]|$)", value)
            return "chrome", m.group(1) if m else value
        if "addons.mozilla.org" in value:
            slug = [p for p in value.rstrip("/").split("/") if p][-1]
            return "firefox", slug
        return browser_hint, value

    if "chromewebstore.google.com" in value or "chrome.google.com/webstore" in value:
        m = re.search(r"/([a-z]{32})(?:[/?]|$)", value)
        if not m:
            print("[ERROR] Could not extract Chrome extension ID from URL.", file=sys.stderr)
            sys.exit(1)
        return "chrome", m.group(1)

    if "addons.mozilla.org" in value:
        slug = [p for p in value.rstrip("/").split("/") if p][-1]
        return "firefox", slug

    if CHROME_ID_RE.match(value):
        return "chrome", value

    # Default: treat as Firefox slug
    return "firefox", value


# ---------------------------------------------------------------------------
# Chrome
# ---------------------------------------------------------------------------

def fetch_chrome_metadata(ext_id: str) -> dict:
    """Scrape the Chrome Web Store page for display metadata."""
    url = CHROME_STORE_URL.format(id=ext_id)
    meta = {
        "extension_id": ext_id,
        "browser": "chrome",
        "name": "",
        "publisher": "",
        "publisher_verified": False,
        "version": "",
        "last_updated": "",
        "description": "",
        "install_count": 0,
        "average_rating": 0.0,
        "rating_count": 0,
        "store_url": url,
    }
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=15, allow_redirects=True)
        if r.status_code != 200:
            return meta
        html = r.text
        # Name and description from OG tags
        name_m = re.search(r'<meta property="og:title" content="([^"]+)"', html)
        if name_m:
            meta["name"] = name_m.group(1).replace(" - Chrome Web Store", "").strip()
        desc_m = re.search(r'<meta property="og:description" content="([^"]+)"', html)
        if desc_m:
            meta["description"] = desc_m.group(1)
        # User count
        users_m = re.search(r"([\d,]+)\s+users", html)
        if users_m:
            meta["install_count"] = int(users_m.group(1).replace(",", ""))
        # Rating
        rating_m = re.search(r"(\d\.\d+)\s+out of\s+5", html)
        if rating_m:
            meta["average_rating"] = float(rating_m.group(1))
        # Rating count
        rcount_m = re.search(r"([\d,]+)\s+ratings", html)
        if rcount_m:
            meta["rating_count"] = int(rcount_m.group(1).replace(",", ""))
    except Exception as e:
        print(f"[!] Store page scrape failed: {e}", flush=True)
    return meta


def download_crx(ext_id: str, dest: pathlib.Path) -> pathlib.Path:
    url = CHROME_CRX_URL.format(id=ext_id)
    r = requests.get(url, headers={"User-Agent": UA}, stream=True, timeout=120, allow_redirects=True)
    r.raise_for_status()
    crx_path = dest / "extension.crx"
    with open(crx_path, "wb") as f:
        for chunk in r.iter_content(65536):
            f.write(chunk)
    return crx_path


def crx_to_zip(crx_path: pathlib.Path, zip_path: pathlib.Path) -> None:
    """Strip CRX2/CRX3 header; extract ZIP portion."""
    data = crx_path.read_bytes()
    zip_start = data.find(b"PK\x03\x04")
    if zip_start == -1:
        raise ValueError("No ZIP signature found in CRX — file may be corrupt or blocked.")
    zip_path.write_bytes(data[zip_start:])


def fetch_chrome(ext_id: str, out_base: pathlib.Path) -> pathlib.Path:
    print(f"[*] Fetching Chrome extension metadata for {ext_id} ...", flush=True)
    metadata = fetch_chrome_metadata(ext_id)

    # Version comes from the manifest inside the CRX — download first
    tmp_dir = out_base / "_chrome_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Downloading CRX ...", flush=True)
    crx_path = download_crx(ext_id, tmp_dir)
    print(f"[*] {crx_path.stat().st_size:,} bytes", flush=True)

    zip_path = tmp_dir / "extension.zip"
    crx_to_zip(crx_path, zip_path)

    # Read version from manifest
    with zipfile.ZipFile(zip_path, "r") as zf:
        if "manifest.json" in zf.namelist():
            mf = json.loads(zf.read("manifest.json"))
            metadata["version"] = mf.get("version", "0.0.0")
            if not metadata["name"]:
                metadata["name"] = mf.get("name", ext_id)
            if not metadata["description"]:
                metadata["description"] = mf.get("description", "")

    name_slug = re.sub(r"[^a-z0-9]+", "-", metadata["name"].lower()).strip("-") or ext_id[:12]
    work_dir = out_base / f"chrome_{name_slug}_{metadata['version']}"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Move zip and extract
    final_zip = work_dir / "extension.zip"
    zip_path.rename(final_zip)
    crx_path.rename(work_dir / "extension.crx")
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)

    ext_dir = work_dir / "ext"
    ext_dir.mkdir(exist_ok=True)
    with zipfile.ZipFile(final_zip, "r") as zf:
        zf.extractall(ext_dir)

    (work_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return work_dir


# ---------------------------------------------------------------------------
# Firefox
# ---------------------------------------------------------------------------

def fetch_firefox(slug: str, out_base: pathlib.Path) -> pathlib.Path:
    print(f"[*] Querying AMO for {slug} ...", flush=True)
    r = requests.get(AMO_API_V4.format(slug=slug), headers={"User-Agent": UA}, timeout=30)
    if r.status_code == 404:
        print(f"[ERROR] Firefox addon '{slug}' not found on AMO.", file=sys.stderr)
        sys.exit(1)
    r.raise_for_status()
    data = r.json()

    cv = data.get("current_version", {})
    files = cv.get("files", [])
    if not files:
        print("[ERROR] No downloadable files in AMO response.", file=sys.stderr)
        sys.exit(1)
    download_url = files[0]["url"]
    version = cv.get("version", "0.0.0")

    authors = data.get("authors", [{}])
    promoted = data.get("promoted", [])
    is_recommended = any(
        "recommended" in p.get("category", "") for p in promoted
    ) if promoted else bool(data.get("is_recommended"))

    name = (data.get("name") or {}).get("en-US") or slug
    description = (data.get("description") or {}).get("en-US", "")

    metadata = {
        "extension_id": slug,
        "browser": "firefox",
        "name": name,
        "publisher": authors[0].get("name", "") if authors else "",
        "publisher_verified": is_recommended,
        "version": version,
        "last_updated": data.get("last_updated", "")[:10],
        "description": description[:200],
        "install_count": int(data.get("average_daily_users", 0)),
        "average_rating": round(float((data.get("ratings") or {}).get("average") or 0), 2),
        "rating_count": int((data.get("ratings") or {}).get("count") or 0),
        "store_url": f"https://addons.mozilla.org/en-US/firefox/addon/{slug}/",
    }

    name_slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or slug[:20]
    work_dir = out_base / f"firefox_{name_slug}_{version}"
    work_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Downloading XPI v{version} ...", flush=True)
    xpi_path = work_dir / "extension.zip"
    rr = requests.get(download_url, headers={"User-Agent": UA}, stream=True, timeout=120)
    rr.raise_for_status()
    with open(xpi_path, "wb") as f:
        for chunk in rr.iter_content(65536):
            f.write(chunk)
    print(f"[*] {xpi_path.stat().st_size:,} bytes", flush=True)

    ext_dir = work_dir / "ext"
    ext_dir.mkdir(exist_ok=True)
    with zipfile.ZipFile(xpi_path, "r") as zf:
        zf.extractall(ext_dir)

    (work_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    return work_dir


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="Chrome/Firefox extension URL or ID/slug")
    ap.add_argument("--out", default="./browser_extension_reviews")
    ap.add_argument("--browser", choices=["chrome", "firefox"], default=None)
    args = ap.parse_args()

    browser, id_or_slug = detect_browser_and_id(args.target, args.browser)
    print(f"[*] Detected browser: {browser}, ID/slug: {id_or_slug}", flush=True)

    out_base = pathlib.Path(args.out).expanduser()
    out_base.mkdir(parents=True, exist_ok=True)

    if browser == "chrome":
        work_dir = fetch_chrome(id_or_slug, out_base)
    else:
        work_dir = fetch_firefox(id_or_slug, out_base)

    meta = json.loads((work_dir / "metadata.json").read_text())
    print(f"[+] {meta['name']} v{meta['version']} — {meta['install_count']:,} installs", flush=True)
    print(f"[+] Working directory: {work_dir}", flush=True)
    print(work_dir)  # machine-readable last line


if __name__ == "__main__":
    main()
