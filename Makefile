PYTHON := .venv/bin/python
OVERLAY := Dopamine-CryptexBootstrap/CryptexBootstrap
PYMOBILEDEVICE_PATCH := Dopamine-CryptexBootstrap/patch_pymobiledevice3_remotexpc.py

.PHONY: python validate build install app on-device-core-test

python: .venv/.ready

.venv/.ready: requirements.txt $(PYMOBILEDEVICE_PATCH)
	python3 -m venv .venv
	$(PYTHON) -m pip install --disable-pip-version-check -r requirements.txt
	$(PYTHON) $(PYMOBILEDEVICE_PATCH)
	touch $@

validate:
	python3 -m py_compile $(OVERLAY)/*.py $(PYMOBILEDEVICE_PATCH)
	zsh -n Dopamine-CryptexBootstrap/setup.sh $(OVERLAY)/build_cryptex.sh
	sh -n $(OVERLAY)/normalize_apt_lists.sh
	plutil -lint $(OVERLAY)/*.plist $(OVERLAY)/SBInject/*.plist >/dev/null
	$(MAKE) on-device-core-test

on-device-core-test:
	swift test --package-path OnDeviceCryptexCore

build: validate
	./Dopamine-CryptexBootstrap/setup.sh --build

install: validate
	./Dopamine-CryptexBootstrap/setup.sh --install

app:
	./MacApp/build_app.sh
