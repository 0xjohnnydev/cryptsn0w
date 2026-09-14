PYTHON := .venv/bin/python

.PHONY: all clean payload python verify

all: python payload

python: .venv/.ready

.venv/.ready: requirements.txt
	python3 -m venv .venv
	.venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt
	touch $@

payload: build/build-summary.json

build/build-summary.json: build.sh Sources/rootd.m Sources/runtime-entitlements.plist Sources/rootd.plist Sources/sshd_config
	./build.sh

verify: all
	$(PYTHON) -m py_compile untitled.py
	plutil -lint Sources/rootd.plist Sources/runtime-entitlements.plist
	/System/Library/SecurityResearch/usr/bin/cryptexctl.research dump-trust-cache $$(find build/unsigned/com.0xjohnnydev.untitled.cxbd/Restore/Cryptex -name gtcd -type f -print -quit) >/dev/null

clean:
	rm -rf build .venv

