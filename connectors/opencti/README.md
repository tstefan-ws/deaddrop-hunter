# OpenCTI connector: deaddrop-hunter

An **external-import** connector that pulls the deaddrop-hunter STIX 2.1 bundle on a
schedule and imports it into OpenCTI. Each import includes:

- indicators (IPv4/IPv6, domains, URLs) with `x_opencti_detection` set when the IOC is
  still served on-chain,
- observables, including OpenCTI's custom `Cryptocurrency-Wallet` observable for dead-drop
  contracts/accounts, operator wallets and payout wallets,
- one `Infrastructure` per dead-drop contract, with a link to its block-explorer page,
- `Malware` objects (XMRig and others) plus the relationships between all of these,
- one `Report` per cluster,
- the author identity `deaddrop-hunter` and the TLP:CLEAR marking on every object.

Default feed URL: `https://tstefan-ws.github.io/deaddrop-hunter/feeds/stix/deaddrop-hunter.bundle.json`

## Compatibility

| OpenCTI platform | `pycti` pin in `requirements.txt` |
|---|---|
| 6.9.x (default) | `pycti==6.9.29` |
| other 6.x | the same major.minor version, e.g. `pycti==6.8.17` for 6.8 |
| 7.x (calendar versions) | the matching `pycti==7.YYMMDD.x` |

`pycti` must match your platform version. The connector uses only APIs that exist
across 6.x and 7.x: `OpenCTIConnectorHelper`, `get_config_variable`,
`helper.api.work.initiate_work` / `to_processed`, `helper.send_stix2_bundle`,
`helper.get_state` / `set_state` and `helper.schedule_iso`. On older helpers it falls
back to `schedule_process`.

## How it works

1. On each run it sends a GET request to `DEADDROP_BUNDLE_URL` with the `If-None-Match` and
   `If-Modified-Since` headers from the previous run. A `304 Not Modified` response ends the run.
2. If the bundle's sha256 matches the last import, the run also ends without sending anything.
3. Otherwise it validates the bundle (a STIX bundle that has an `objects` array).
   With `DEADDROP_ONLY_CURRENT=true` it then drops indicators that are no longer served
   on-chain, together with their relationships.
4. It opens a work item (`initiate_work`), sends the bundle with
   `send_stix2_bundle(..., work_id=..., cleanup_inconsistent_bundle=True)`, and marks the
   work as processed, or as failed if sending raised an error.
5. It saves state: `last_run`, `last_success`, `last_sha256`, `etag` and `last_modified`.

The same input always produces the same STIX ids, so re-imports update existing objects
and do not create duplicates.

## Configuration

| Env var | config.yml | Default | Notes |
|---|---|---|---|
| `OPENCTI_URL` | `opencti.url` | required | |
| `OPENCTI_TOKEN` | `opencti.token` | required | Use a dedicated connector user |
| `CONNECTOR_ID` | `connector.id` | required | A fresh UUIDv4 |
| `CONNECTOR_NAME` | `connector.name` | `deaddrop-hunter` | |
| `CONNECTOR_SCOPE` | `connector.scope` | see sample | |
| `CONNECTOR_LOG_LEVEL` | `connector.log_level` | `info` | |
| `CONNECTOR_DURATION_PERIOD` | `connector.duration_period` | `PT6H` | ISO-8601 interval between runs |
| `DEADDROP_BUNDLE_URL` | `deaddrop.bundle_url` | GitHub Pages URL above | `file:///path` also works |
| `DEADDROP_TIMEOUT` | `deaddrop.timeout` | `60` | HTTP timeout in seconds |
| `DEADDROP_VERIFY_SSL` | `deaddrop.verify_ssl` | `true` | |
| `DEADDROP_ONLY_CURRENT` | `deaddrop.only_current` | `false` | Import only IOCs that are still live |
| `DEADDROP_FORCE_REIMPORT` | `deaddrop.force_reimport` | `false` | Ignore the ETag and sha256 checks |

The project publishes a new feed after every hunt. An interval of 1 to 6 hours is enough.

## Setup

### Docker (recommended)

```bash
cd connectors/opencti
docker build -t deaddrop-hunter/opencti-connector:latest .
```

Add the service from [`docker-compose.yml`](docker-compose.yml) to your OpenCTI stack.
It must be on the same network as the `opencti` service. Then set `OPENCTI_TOKEN` and
`CONNECTOR_ID`, and run:

```bash
docker compose up -d connector-deaddrop-hunter
docker compose logs -f connector-deaddrop-hunter
```

### Manual (virtualenv)

```bash
cd connectors/opencti
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp src/config.yml.sample src/config.yml   # then edit url / token / id
cd src && python3 main.py
```

After the first run, check **Data → Ingestion → Connectors → deaddrop-hunter**. The work
item shows the number of bundles processed. Then look under **Analyses → Reports**, where
the author is `deaddrop-hunter`.

## Notes

- `cryptocurrency-wallet` is an **OpenCTI-specific** custom observable. Other STIX
  consumers ignore it or keep it as a custom object.
- No indicators are created for wallets or contracts. They are imported as observables
  linked to the contract infrastructure (`consists-of` / `related-to`).
- Tests: `PYTHONPATH=src python -m pytest tests/exporters -q` from the repo root, with
  `pycti` mocked.
