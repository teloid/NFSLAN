# Console Worker Notes

`NFSLAN.exe` can still be used directly.

## Basic

```bash
NFSLAN "Test Server"
```

With explicit U2 mode:

```bash
NFSLAN "Test Server" --u2-mode 0
```

## Notes

- `-n` is deprecated in this fork path and ignored in worker flow.
- Worker expects `server.dll` + `server.cfg` in working directory.
- For this release, use U2 `server.dll`.
