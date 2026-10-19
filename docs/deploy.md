# Deploying deaddrop-hunter

Three ways to run it. They can be combined: e.g. run the hunter from WSL with your own API keys
and let GitHub Pages host the dashboard (path B with `--push`).

| | A. GitHub Pages + Actions | B. WSL / Linux self-hosted | C. Docker |
|---|---|---|---|
| Cost | free (public repo) | free | free |
| Runs hunts | GitHub Actions, every 6 h | cron or systemd timer | container loop, every 6 h |
| Dashboard | `https://tstefan-ws.github.io/deaddrop-hunter/` | `http://localhost:8080` (or Pages via `--push`) | `http://localhost:8080` |
| Keys | Actions secrets | `.env` | `.env` |

---

## A. GitHub Pages + GitHub Actions

### Free-plan facts (GitHub Free, account `tstefan-ws`)

- The repository must be **public** to get GitHub Pages for free and **unlimited Actions
  minutes** on standard GitHub-hosted runners.
- **Pages sites are public**, even though the data is TLP:CLEAR anyway.
- GitHub **disables scheduled workflows in public repos after 60 days without repository
  activity**. The hunt's own data commits normally count as activity and keep it alive; if it
  is ever disabled, re-enable it with one click in the *Actions* tab (`hunt` -> *Enable workflow*).

### 1. Create the repo and push

With the GitHub CLI (from the project directory):

```bash
gh auth login
git init -b main            # if not already a git repo
git add -A && git commit -m "Initial import"
gh repo create tstefan-ws/deaddrop-hunter --public --source . --push
```

Or in the browser: *New repository* -> name `deaddrop-hunter`, **Public**, no README; then

```bash
git remote add origin https://github.com/tstefan-ws/deaddrop-hunter.git
git push -u origin main
```

Make sure the shell scripts keep their executable bit (the repo's `.gitattributes` keeps them LF):

```bash
git update-index --chmod=+x scripts/*.sh && git commit -m "scripts: mark executable" && git push
```

### 2. Repository settings

1. *Settings -> Pages -> Build and deployment -> Source*: **GitHub Actions**.
2. *Settings -> Actions -> General -> Workflow permissions*: **Read and write permissions**
   (the hunt commits `data/` back). Leave "Allow GitHub Actions to create and approve pull
   requests" off.
3. Optional secrets: *Settings -> Secrets and variables -> Actions -> New repository secret*.
   All optional; names must match exactly:

| Secret | Enables |
|---|---|
| `ETHERSCAN_API_KEY` | EVM operator wallet watches, Etherscan fallbacks (free plan excludes BSC) |
| `DUNE_API_KEY` | BSC event sweeps (`bnb.logs`) and selector hunts |
| `TRONGRID_API_KEY` | Higher TronGrid rate limit |
| `DDH_RPC_BSC` | Keyed BSC RPC for topic sweeps, `url\|max_span` |
| `DDH_RPC_BSC_TESTNET` | Same for BSC testnet |
| `DDH_RPC_SOLANA` | Solana RPC override |
| `VT_API_KEY` | VirusTotal enrichment (reserved) |

With the CLI: `gh secret set DUNE_API_KEY --repo tstefan-ws/deaddrop-hunter` (prompts for the value).

### 3. First run

*Actions -> hunt -> Run workflow* (branch `main`). Optional inputs: `chains`
(e.g. `polygon`), `days` (look-back for chains without a cursor), `hunts`.
Or: `gh workflow run hunt.yml --repo tstefan-ws/deaddrop-hunter -f chains=polygon -f days=30`.

The run has two jobs: **hunt** (sweeps, commits `data: hunt <timestamp>` if anything changed)
and **deploy / build + deploy** (export feeds and API, build the site, publish). When it
finishes, the URL is shown on the deploy job and under *Settings -> Pages*:

**<https://tstefan-ws.github.io/deaddrop-hunter/>** - API: `.../feeds/api/v1/index.json`.

From then on `hunt.yml` runs every 6 hours (`17 */6 * * *` UTC). Changes to `web/`,
`scripts/build_site.py` or the exporters on `main` redeploy the site via `deploy-pages.yml`.

### Troubleshooting

| Symptom | Fix |
|---|---|
| `remote: Permission to ... denied to github-actions[bot]` | Workflow permissions -> Read and write (step 2.2) |
| Deploy job: "Get Pages site failed" / 404 | Pages source must be "GitHub Actions" (step 2.1) |
| `Branch "x" is not allowed to deploy to github-pages` | Deploy only from `main`, or edit *Settings -> Environments -> github-pages* |
| BSC always `skipped` | Expected without `DUNE_API_KEY` or `DDH_RPC_BSC` |
| Scheduled runs stopped | 60-day inactivity rule: re-enable in the Actions tab |

---

## B. WSL (Ubuntu on Windows) / Linux, self-hosted

### 1. Install and first run

In a fresh Ubuntu WSL shell:

```bash
sudo apt update && sudo apt install -y python3 python3-venv git
cd ~                                    # Linux filesystem, NOT /mnt/c (much faster)
git clone https://github.com/tstefan-ws/deaddrop-hunter.git
cd deaddrop-hunter
bash scripts/bootstrap_wsl.sh           # idempotent: .venv, pip install, .env, first short hunt
```

> Keep the repo inside the Linux filesystem (`~/deaddrop-hunter`). Working under `/mnt/c/...`
> goes through the Windows file bridge and is many times slower for git and Python; the
> bootstrap script warns if it detects that.

The manual equivalent of the bootstrap:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .                        # add ".[dev]" for tests/linting
cp .env.example .env && chmod 600 .env  # optional keys
deaddrop-hunter hunt --chains polygon --days 7
deaddrop-hunter export --data data --out site/feeds --formats stix,misp,csv,txt,api
python scripts/build_site.py --out site
```

### 2. Serve the dashboard

```bash
python3 -m http.server -d site 8080
```

Open <http://localhost:8080> in your Windows browser (WSL2 forwards localhost automatically).
`make serve` does the same.

### 3. Keys

Put keys in `.env` in the repo root (format `KEY=value`, see `.env.example`). `.env` is in
`.gitignore`; never commit it. `scripts/run_hunt.sh` loads it on every run.

### 4. One full cycle

```bash
scripts/run_hunt.sh                         # hunt -> export -> build_site
scripts/run_hunt.sh --chains polygon --days 3
scripts/run_hunt.sh --push                  # also commit + push data/ (Pages hosting)
scripts/run_hunt.sh --no-site               # hunt only
```

Extra arguments are passed to `deaddrop-hunter hunt`. A lock file prevents overlapping runs.

**Hunting locally but hosting on GitHub Pages**: set up path A, clone with push rights (SSH key or
`gh auth login`), and schedule `scripts/run_hunt.sh --push`. The pushed data commit lands on
`main`; the next scheduled `hunt.yml` run (or a manual *deploy-pages* run) publishes it. If you
only want your local runs, disable the `hunt` workflow in the Actions tab to avoid two hunters
racing on `data/`.

### 5. Scheduling

Logs go to `logs/hunt.log` in the examples below (`logs/` is git-ignored).

**Option 1 - cron.** WSL does not start services automatically unless systemd is enabled, so
start cron first:

```bash
sudo apt install -y cron
sudo service cron start                     # needed after every WSL restart without systemd
crontab -e
```

```cron
# every 6 hours at minute 17
17 */6 * * * cd $HOME/deaddrop-hunter && scripts/run_hunt.sh >> logs/hunt.log 2>&1
```

To start cron automatically without systemd, add to `/etc/wsl.conf`:

```ini
[boot]
command = service cron start
```

**Option 2 - systemd user timer** (recommended on recent WSL). Enable systemd once:

```ini
# /etc/wsl.conf
[boot]
systemd=true
```

Then in PowerShell: `wsl --shutdown`, reopen Ubuntu, and create the units:

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/deaddrop-hunter.service <<'EOF'
[Unit]
Description=deaddrop-hunter: hunt, export, build site

[Service]
Type=oneshot
WorkingDirectory=%h/deaddrop-hunter
ExecStart=/bin/bash -c 'scripts/run_hunt.sh >> logs/hunt.log 2>&1'
EOF

cat > ~/.config/systemd/user/deaddrop-hunter.timer <<'EOF'
[Unit]
Description=Run deaddrop-hunter every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:17:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now deaddrop-hunter.timer
loginctl enable-linger "$USER"          # keep user timers running without an open session
systemctl --user list-timers
```

Logs: `logs/hunt.log`, plus `journalctl --user -u deaddrop-hunter.service`.
Run now: `systemctl --user start deaddrop-hunter.service`.

Note: WSL shuts the VM down a while after the last terminal closes. For truly unattended
runs keep a session open, start WSL from Windows Task Scheduler (`wsl.exe -d Ubuntu --exec
/bin/true` at logon), or use path A.

### 6. Serve continuously (optional)

```bash
nohup python3 -m http.server -d site 8080 > logs/http.log 2>&1 &
```

`build_site.py` rewrites `site/` in place, so a running server picks up new builds.

---

## C. Docker (optional)

Works on Docker Desktop (WSL 2 backend) or `docker-ce` inside WSL / Linux. Requires Docker
Compose v2.24+ (optional `env_file`).

```bash
cp .env.example .env        # optional keys
docker compose up -d --build
docker compose logs -f hunter
```

- `hunter` (built from `Dockerfile`, non-root) runs `scripts/run_hunt.sh` in a loop every
  `HUNT_INTERVAL_SECONDS` (default 21600 = 6 h). `./data` and `./site` are bind-mounted, so
  results persist and stay in your git checkout.
- `web` (`nginx:alpine`) serves `./site` read-only on <http://localhost:8080> (bound to
  127.0.0.1 only).
- One-off run: `docker compose run --rm hunter scripts/run_hunt.sh --chains polygon --days 3`.
- Update: `git pull && docker compose up -d --build`.

If `./data` or `./site` were created by root, fix ownership for the container's UID 1000:
`sudo chown -R 1000:1000 data site`.

---

## Security notes for all paths

- The hunter is read-only and never contacts decoded IOCs; still, run it on a machine where
  outbound HTTPS to RPC providers is acceptable (the Sigma/Suricata rules in `rules/` will
  flag it - that is expected; exclude the host).
- Never commit `.env` or paste keys into issues. Rotate a key if it leaks.
- The published site and API are public by design (TLP:CLEAR).
