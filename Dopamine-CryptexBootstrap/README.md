# Dopamine Cryptex bootstrap overlay

**Redacted source:** TSS request construction, personalization, and related
installation details are intentionally omitted. The files retain placeholders
for educational reference.

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

[REDACTED: Related request, payload, or installation details omitted.]

The build scripts contain the development identity and profile path used on
the original Mac as defaults. Override them with the documented
`CODEX_SILEO_*` environment variables on another host.
