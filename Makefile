PYTHON := .venv/bin/python
OVERLAY := Dopamine-CryptexBootstrap/CryptexBootstrap
PYMOBILEDEVICE_PATCH := Dopamine-CryptexBootstrap/patch_pymobiledevice3_remotexpc.py

.PHONY: python validate test build install app

python: .venv/.ready

.venv/.ready: requirements.txt $(PYMOBILEDEVICE_PATCH)
	python3 -m venv .venv
	$(PYTHON) -m pip install --disable-pip-version-check -r requirements.txt
	$(PYTHON) $(PYMOBILEDEVICE_PATCH)
	touch $@

validate:
	python3 -m py_compile $(OVERLAY)/*.py $(PYMOBILEDEVICE_PATCH)
	@set -e; for script in Dopamine-CryptexBootstrap/setup.sh $(OVERLAY)/build_cryptex.sh MacApp/build_app.sh; do \
		zsh -n "$$script"; \
	done
	sh -n $(OVERLAY)/normalize_apt_lists.sh
	plutil -lint $(OVERLAY)/*.plist $(OVERLAY)/SBInject/*.plist >/dev/null

test: validate
	swift test --package-path MacApp

build: validate
	./Dopamine-CryptexBootstrap/setup.sh --build

install: validate
	./Dopamine-CryptexBootstrap/setup.sh --install

app:
	./MacApp/build_app.sh
