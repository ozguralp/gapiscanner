# gapiscanner 2.0.0

Version 2 expands Google Maps API Scanner into gapiscanner, with Google API checks and web/mobile key discovery.

## Features

- Selected Gemini, Firebase, Identity Toolkit, Vertex AI and Google Cloud checks.
- Google Maps Platform checks through `--include-maps`.
- Website and APK/IPA key discovery.
- Client restriction contexts and a local key knowledge base.
- Resumable URL discovery and aggregate JSON reports.
- Separate options for authorization, authenticated reads, write operations and paid-operation checks.

## Installation and usage

The Python package, command and Docker entry point are all named `gapiscanner`.

```bash
pipx install git+https://github.com/ozguralp/gapiscanner
gapiscanner --help
```

The Python API and JSON result format changed in this major version.

## Reliability

- Stronger response validation and clearer request-error reporting.
- Improved credential redaction and request isolation.
- More reliable discovery caching, mobile extraction and local state handling.
- Updated installation instructions, Docker packaging and offline tests.

The default scan includes generation and anonymous account creation with attempted cleanup. `--include-destructive` enables writes that may leave resources behind. `--include-cost-amp` can consume quota or incur charges. `--all` enables both groups alongside Maps and low-category checks. See the README for details.
