# deaddrop-hunter - convenience targets (Linux / WSL / macOS).
# Uses .venv when present; override with `make PY=python3.12 ...`.

VENV    ?= .venv
PY      ?= $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)
DATA    ?= data
SITE    ?= site
PORT    ?= 8080
CHAINS  ?=
DAYS    ?=

HUNT_ARGS := --config config/hunts.toml --data $(DATA)
ifneq ($(strip $(CHAINS)),)
HUNT_ARGS += --chains $(CHAINS)
endif
ifneq ($(strip $(DAYS)),)
HUNT_ARGS += --days $(DAYS)
endif

.PHONY: help install test lint hunt export site serve all clean rules-check

help:
	@echo "make install          create .venv and install with dev extras"
	@echo "make test | lint      pytest | ruff"
	@echo "make hunt [CHAINS=polygon DAYS=3]"
	@echo "make export           feeds + public API into $(SITE)/feeds"
	@echo "make site             assemble $(SITE)/ (keeps $(SITE)/feeds)"
	@echo "make serve [PORT=8080]"
	@echo "make all              hunt + export + site"
	@echo "make clean            remove $(SITE)/ and caches (never touches data/)"

$(VENV)/bin/python:
	python3 -m venv $(VENV)

install: $(VENV)/bin/python
	$(VENV)/bin/python -m pip install --upgrade pip
	$(VENV)/bin/python -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests

hunt:
	$(PY) -m deaddrop_hunter hunt $(HUNT_ARGS)

export:
	mkdir -p $(SITE)/feeds
	$(PY) -m deaddrop_hunter export --data $(DATA) --out $(SITE)/feeds --formats stix,misp,csv,txt,api

site:
	$(PY) scripts/build_site.py --out $(SITE) --web web --data $(DATA)

serve:
	@echo "Serving $(SITE)/ on http://localhost:$(PORT)  (Ctrl+C to stop)"
	$(PY) -m http.server -d $(SITE) $(PORT)

all: hunt export site

rules-check:
	$(PY) -m pip install --quiet sigma-cli yara-python
	sigma check rules/sigma
	$(PY) -c "import glob,yara; [yara.compile(filepath=f) for f in glob.glob('rules/yara/*.yar')]; print('yara ok')"

clean:
	rm -rf $(SITE) .pytest_cache .ruff_cache build dist src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
