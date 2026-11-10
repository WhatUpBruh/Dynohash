PYTHON := .venv/bin/python
UBUNTU_VERSION := $(shell lsb_release -rs 2>/dev/null)
P4LANG_REPO := https://download.opensuse.org/repositories/home:/p4lang/xUbuntu_$(UBUNTU_VERSION)

.PHONY: init venv system-deps topology collector adaptive adaptive-live

# One-time setup: Python env + the system/P4 toolchain. Safe to re-run.
init: venv system-deps

venv:
	python3 -m venv .venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r tools/p4runtime-requirements.txt

system-deps:
	sudo apt-get update
	sudo apt-get install -y mininet libjsoncpp-dev libxxhash-dev
	echo 'deb $(P4LANG_REPO)/ /' | sudo tee /etc/apt/sources.list.d/home_p4lang.list
	curl -fsSL $(P4LANG_REPO)/Release.key | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/home_p4lang.gpg
	sudo apt-get update
	sudo apt-get install -y p4lang-p4c p4lang-bmv2

# Terminal A: start the Mininet/BMv2 topology. Leave this running.
topology:
	sudo /usr/bin/python3 tests/topology/dynohash_detectors.py

# Terminal B: start the telemetry collector. Leave this running.
collector:
	$(PYTHON) -m detectors.collector --bind 172.18.50.1 --port 8080

# Terminal C: run the adaptive controller (dry-run; no switch writes).
adaptive:
	$(PYTHON) -m controller.adaptive_cli --iterations 60

# Terminal C, live variant: performs one real guarded migration.
adaptive-live:
	$(PYTHON) -m controller.adaptive_cli --iterations 60 --live --acknowledge-state-loss
