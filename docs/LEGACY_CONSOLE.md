# Legacy Console Worker Notes

The original project behavior is preserved in the Windows worker executable (`NFSLAN.exe`).

## Basic usage

```bash
NFSLAN YourServerName
```

Optional:

```bash
NFSLAN YourServerName -n
```

`-n` disables runtime patching.

## Required files

Place next to worker executable or set worker working directory to contain:

- `server.dll`
- `server.cfg`

Use the correct game-specific `server.dll` (MW and UG2 are different).

## Existing config notes

- `PORT` sets listening port (commonly `9900`)
- `ADDR` affects advertised listen address
- Logging keys like `LOGCONNECTIONS`, `log.level`, `log.categoryMask` can adjust diagnostics

Some `server.cfg` keys remain reverse-engineering dependent and are still not fully documented.
