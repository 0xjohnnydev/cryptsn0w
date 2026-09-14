# Dopamine Cryptex bootstrap overlay

This directory contains the custom source added on top of opa334/Dopamine 3.x.
The public upstream repository and its 239 MiB Git history are intentionally
not duplicated here.

Pinned upstream:

- repository: `https://github.com/opa334/Dopamine.git`
- branch: `3.x`
- commit: `939a3a2` (`Print backtrace on darksword / clearsword krw failure`)

To reconstruct the working tree from the root of this private repository:

```sh
git clone --branch 3.x https://github.com/opa334/Dopamine.git Dopamine-upstream
git -C Dopamine-upstream checkout 939a3a2
rsync -a Dopamine-CryptexBootstrap/CryptexBootstrap/ \
  Dopamine-upstream/CryptexBootstrap/
cd Dopamine-upstream
```

The sibling `tools/cryptexd-static` directory supplies the personalizer used
by `CryptexBootstrap/README.md`. The source snapshot also includes the final
v52/v36 runbook and proof metadata, but not the device-bound tickets, signed
Cryptex bundle, IPA, provisioning profile, or logs.

The build scripts contain the development identity and profile path used on
the original Mac as defaults. Override them with the documented
`CODEX_SILEO_*` environment variables on another host.
