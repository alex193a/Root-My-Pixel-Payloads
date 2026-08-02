# Root My Pixel Payloads

Native exploit payloads for Google Pixel devices.

## Available targets

The `src/targets/` directory contains **35 target definitions** ported from
the [IonStack](https://github.com/NebuSec/CyberMeowfia) project, covering
multiple Pixel devices and firmware versions (CP1A through CP2A).

To see the full list:

```sh
ls src/targets/
```

## How it works

1. **CVE-2026-43499** (GhostLock) — futex PI stack UAF
   - KASLR bypass via KernelSnitch or P0 Physical Oracle
   - Arbitrary kernel R/W via pipe buffer corruption + ashmem
   - CFI bypass via fake file_operations
   - Root + SELinux permissive via credential/SID patching

2. **Root daemon** — spawns via `call_usermodehelper`
   - Listens on Unix socket for commands
   - Launches `ksud late-load` to install ReSukiSU

3. **KernelSU late-load** — uses vanilla ReSukiSU
   - Loads via standard `init_module` syscall
   - Verified via ioctl on `/dev/kernelsu`

## Build

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk

# Build for a specific target
make TARGET=frankel-CP2A.260605.012

# Or use convenience targets
make pixel9pro       # frankel-CP2A.260605.012
make pixel9          # tokay-CP2A.260605.012
make pixel9proxl     # komodo-CP2A.260605.012.C1
make pixel9a         # mustang-CP2A.260605.012
make pixel8pro       # comet-CP2A.260605.012
make pixel8a         # rango-CP2A.260605.012
make pixel7          # panther-CP2A.260605.012
make pixel6          # oriole-CP2A.260605.012
make pixel10proxl    # mustang-CP2A.260705.006
```

## Credits

- Exploit: [NebuSec IonStack](https://github.com/NebuSec/CyberMeowfia)
- App architecture: Adapted from [Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)