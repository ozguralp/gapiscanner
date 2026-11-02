# gapiscanner — Google API Scanner

gapiscanner discovers Google API keys in websites and mobile applications, then checks their access to selected Google APIs.

Originally released as Google Maps API Scanner, version 2 adds Gemini, Firebase, Identity Toolkit, Vertex AI and selected Google Cloud checks alongside the existing Maps coverage.

## Installation

Requires Python 3.9 or newer with OpenSSL 1.1.1 or newer.

With pipx installed:

```bash
pipx install git+https://github.com/ozguralp/gapiscanner
gapiscanner --help
```

For a source checkout:

```bash
git clone https://github.com/ozguralp/gapiscanner.git
cd gapiscanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
gapiscanner --help
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1`. On macOS, use Python from python.org or Homebrew if the system interpreter uses unsupported LibreSSL.

The base installation requires only Requests. Poetry, Java, Go and a browser are not required for direct key checks or basic APK/IPA extraction.

## Basic usage

Use the scanner only on assets you are authorized to test. The default scan includes a small Gemini generation request and anonymous Identity Toolkit account creation followed by attempted deletion. These requests can consume quota, incur charges or leave an account if cleanup fails.

Scan a key:

```bash
gapiscanner --api-key KEY
```

Add Google Maps Platform checks:

```bash
gapiscanner --api-key KEY --include-maps
```

Discover and test keys in a website or mobile application:

```bash
gapiscanner --url https://target.example
gapiscanner --mobile app.apk
gapiscanner --mobile app.ipa
gapiscanner --mobile-dir ./mobile-bundles
```

For all available options:

```bash
gapiscanner --help
```

## Additional checks and risks

Enable each group only when its operations are permitted for the target. Maps and low-category checks can also consume quota or incur charges.

### Write and create operations

```bash
gapiscanner --api-key KEY --include-destructive
```

This enables resource-creation and write attempts, including Gemini resources and Firebase database test writes when a project is identified. Successful requests can change project data, create stored resources and incur charges. Cleanup is attempted where supported, but it can fail and leave artifacts. If `--it-test-email` or `--it-test-phone` is also supplied, the scanner can send authentication emails or SMS messages to that address or number.

### Paid operation checks

```bash
gapiscanner --api-key KEY --include-cost-amp
```

This enables probes for image, video, music, speech and video-analysis operations. The probes use minimal request bodies, but accepted requests can consume service quota, start processing jobs or incur charges. Do not assume every request will be rejected before billing.

### Combined scan

```bash
gapiscanner --api-key KEY --all
```

This combines the default checks with Maps, low-category, destructive and cost-amplification groups. It carries the write, cleanup, quota and billing risks described above and sends more requests than the default scan. Authorization-key and authenticated-read checks remain separate opt-ins.

Add utility and billing checks:

```bash
gapiscanner --api-key KEY --include-low
```

## Client restrictions

Supply the original client context when testing a restricted key:

```bash
gapiscanner --api-key KEY --restriction-mode referer --restriction-value https://target.example
gapiscanner --api-key KEY --restriction-mode android --restriction-value com.example.app:0123456789ABCDEF0123456789ABCDEF01234567
gapiscanner --api-key KEY --restriction-mode ios --restriction-value com.example.app
```

Replace the example package, bundle ID and certificate fingerprint with values from the application being tested.

Keys discovered on websites are also tested with an in-scope source URL as the Referer. Use `--no-auto-referer` to disable this second pass. An explicit restriction mode also disables automatic replay.

Proxy example:

```bash
gapiscanner --api-key KEY --proxy http://127.0.0.1:8080
```

## Results and output

- `CONFIRMED`: the response satisfies the probe's success criteria.
- `POTENTIAL`: additional verification is required.

Finding a key or receiving a successful API response does not automatically establish a vulnerability. Interpret results in the context of the affected application and its intended access controls.

```bash
gapiscanner --api-key KEY --json
gapiscanner --api-key KEY --output results.json
gapiscanner --url https://target.example --output results.json
```

`--json` writes JSON to stdout and progress messages to stderr. URL and mobile output combines discovered keys and their restriction passes into one report.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No confirmed HIGH/CRITICAL finding; scan complete |
| `1` | Confirmed HIGH/CRITICAL finding |
| `2` | Input, validation or output-writing error |
| `3` | No confirmed HIGH/CRITICAL finding, but scan incomplete |
| `130` | Interrupted |

With `--exit-on-any-confirmed`, any confirmed finding produces exit code `1`.

## Website discovery and resume

Set a fetch budget when needed:

```bash
gapiscanner --url https://target.example --url-fetch-budget 500
```

Save and resume the discovery queue:

```bash
gapiscanner --url https://target.example --url-fetch-state ./url-queue.json
gapiscanner --url https://target.example --url-fetch-state ./url-queue.json --resume
```

Keep the state file and its adjacent `url-queue.json.cache/` directory together. Missing or corrupt cached responses are fetched again. Pending URLs and failed fetches produce exit code `3`.

## Optional discovery dependencies

For Android package and signing-certificate extraction:

```bash
pipx inject gapiscanner "androguard>=4,<5"
```

For browser-rendered JavaScript discovery:

```bash
pipx inject --include-apps gapiscanner playwright
playwright install chromium
```

Use `--no-playwright` to disable browser discovery. Katana is used as an additional crawl tier when installed and available on PATH.

For SOCKS proxies:

```bash
pipx inject gapiscanner PySocks
```

When using a virtual environment, install optional dependencies into that same environment with `python -m pip install`.

## Authorization-key checks

Service-account-bound authorization keys have a separate opt-in group:

```bash
gapiscanner --api-key KEY --project-id PROJECT_ID --include-authorization-key
```

To run only that group:

```bash
gapiscanner --api-key KEY --project-id PROJECT_ID --authorization-only
```

The group checks Vertex AI countTokens and three IAM-protected inventory methods: models, datasets and endpoints. Inventory checks use `us-central1`. Results apply to the operations and region tested.

Authenticated Firebase reads can be enabled with `--include-auth-read`. These checks use a temporary anonymous identity and may return project data; use this option only when account creation and those reads are authorized.

## Local key knowledge base

Inspect, rescan or export locally recorded keys:

```bash
gapiscanner --show-kb
gapiscanner --rescan-kb
gapiscanner --rescan-kb --authorization-only
gapiscanner --export-kb-csv key-review.csv
```

Stored mobile restriction contexts and known project identifiers can be reused during rescans.

| Platform | Default data directory |
| --- | --- |
| macOS | `~/Library/Application Support/gapiscanner` |
| Linux | `$XDG_DATA_HOME/gapiscanner` or `~/.local/share/gapiscanner` |
| Windows | `%LOCALAPPDATA%\gapiscanner` |

Set `GAPISCANNER_DATA_DIR` to use another directory. `--output-dir DIR` places the key knowledge base directly in `DIR`.

The knowledge base, CSV exports, response caches and generated `jsapi_test.html` can contain raw keys. Keep these files private. Report JSON and console diagnostics redact keys. Use `--no-jsapi` to disable HTML generation.

## Docker

```bash
docker build -t gapiscanner .
docker run --rm gapiscanner --help
docker run --rm gapiscanner --api-key KEY
docker run --rm gapiscanner --api-key KEY --include-maps --no-jsapi
```

The container runs as UID 10001. `/work` is the working directory and `/data` holds persistent scanner state. Mount a writable volume at `/data` to preserve that state. Optional browser and Android parsers are not included in the base image.

## Tests

```bash
python -m pip install -e . pytest pytest-cov pytest-mock
python -m pytest
```

The automated test suite runs offline and blocks network access.

## Background

- [Unauthorized Google Maps API key usage](https://medium.com/bugbountywriteup/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e)
- [Google Maps API bugs found over the years](https://medium.com/bugbountywriteup/google-maps-api-not-the-key-bugs-that-i-found-over-the-years-781840fc82aa)

## License

MIT. See [LICENSE](LICENSE).
