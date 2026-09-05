/*
 * OpenIPC network flasher for FH8856 -- runs as /init from a kernel-embedded
 * initramfs.
 *
 * Why this exists: on the running VENDOR firmware the rootfs partition cannot
 * be rewritten. The SoC watchdog is held by `ipcam` and fires ~32s after the
 * feeder stops; overwriting mtd2 stops the feeder, and the only byte-exact
 * write method manages ~76 KB/s, so the 3.1 MB landing in mtd2 needs ~42s.
 * The write loses that race -- that is how 131 got bricked.
 *
 * So the rootfs is not written from the vendor system at all. The vendor side
 * only writes THIS into the kernel partition, which the prior analysis showed
 * is safe while ipcam is alive. On the next boot the vendor userland is gone
 * and the flash writes have no deadline.
 *
 * Two deliberate choices:
 *
 *  - We never open /dev/watchdog. fh_wdt runs in WDT_TIMER_MODE where a kernel
 *    timer does the real hardware kick, under the condition
 *        time_before(jiffies, next_heartbeat) || (!nowayout && !in_use)
 *    CONFIG_WATCHDOG_NOWAYOUT is off here, so while NOTHING holds the device
 *    the kernel kicks it forever and there is no deadline at all. Opening it
 *    sets in_use and drops the hardware timeout to 2s, manufacturing the very
 *    problem this design exists to avoid. (An earlier version opened it and
 *    pinged with write(); fh_wdt_write() calls mod_timer(jiffies + HZ/2), so
 *    petting faster than twice a second perpetually DEFERS the timer that does
 *    the hardware kick. It reset the board 2.5MB into the download.)
 *
 *  - Writes are addressed by ABSOLUTE FLASH OFFSET, not by partition name.
 *    This image has to run under whatever mtdparts the current environment
 *    happens to declare -- on a still-vendor camera that is the vendor layout,
 *    where no partition is called "rootfs". Partitions are contiguous from 0,
 *    so /proc/mtd gives us the map and we span boundaries as needed. That
 *    removes the ordering trap where the env must be written before the kernel.
 *
 * No busybox: a static binary is ~55 KB against busybox's 789 KB plus a 620 KB
 * musl, which would not fit the 2048K kernel slot alongside the kernel. It also
 * lets eth0 be configured with plain SIOCSIFADDR ioctls -- every netlink route
 * (RTM_GETLINK) oopses this 3.0.8 kernel.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>

#include "images.h"   /* generated: IMG_* names, sizes, crc32s */

/*
 * Network configuration is READ FROM THE U-BOOT ENVIRONMENT IN FLASH.
 *
 * One prebuilt uImage.flasher has to work on anybody's network, and the config
 * cannot be patched into the image at flash time because the initramfs lives
 * inside the compressed kernel. The host tool therefore writes the addressing
 * into the env sector (0x40000) before it writes this kernel, leaving the
 * vendor bootargs/bootcmd untouched so a stock boot is unaffected, and we read
 * it back out of flash here.
 *
 * An earlier version broadcast a BOOTP-style request instead. It is a nicer
 * idea and it did not work: with no address yet the request goes out with
 * source 0.0.0.0, which firewalls routinely drop (DHCP survives only because
 * it gets explicit rules). On the bench it silently found nothing and the
 * conversion succeeded purely on the compile-time fallback -- which is exactly
 * the failure that would strand a camera on a network unlike ours. Reading the
 * env needs no network at all, so nothing can filter it.
 */
#ifndef CAM_IP
#define CAM_IP   "10.81.81.60"
#endif
#ifndef SRV_IP
#define SRV_IP   "10.81.81.1"
#endif
#ifndef GW_IP
#define GW_IP    ""          /* empty = same subnet, no route needed */
#endif
#ifndef NETMASK
#define NETMASK  "255.255.255.0"
#endif
#define IFNAME   "eth0"

/* Absolute flash offsets. These are properties of the chip layout, not of any
 * mtdparts string, which is exactly why they are used directly. */
#define OFF_ENV     0x40000UL
#define OFF_KERNEL  0x50000UL
#define OFF_ROOTFS  0x250000UL
#define ENV_SIZE    0x10000UL

#ifndef TFTP_PORT
#define TFTP_PORT 69
#endif

/* Filled by load_cfg() from the flash env, else the compile-time defaults. */
static char cfg_ip[24]   = CAM_IP;
static char cfg_mask[24] = NETMASK;
static char cfg_gw[24]   = GW_IP;
static char cfg_srv[24]  = SRV_IP;
static int  cfg_port     = TFTP_PORT;
#define BLK       512
#define CHUNK     (64 * 1024)

static unsigned long crc_tab[256];
static void crc_init(void)
{
    for (unsigned long i = 0; i < 256; i++) {
        unsigned long c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320UL ^ (c >> 1) : c >> 1;
        crc_tab[i] = c;
    }
}
static unsigned long crc32b(const unsigned char *p, unsigned long n)
{
    unsigned long c = 0xFFFFFFFFUL;
    for (unsigned long i = 0; i < n; i++)
        c = crc_tab[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFUL;
}

/* ---- flash map ------------------------------------------------------- */

struct part { int idx; unsigned long base, size; char name[64]; };
static struct part parts[16];
static int nparts;

static int read_mtd_table(void)
{
    FILE *f = fopen("/proc/mtd", "r");
    if (!f) { perror("/proc/mtd"); return -1; }
    char line[256];
    unsigned long base = 0;
    nparts = 0;
    while (fgets(line, sizeof line, f) && nparts < 16) {
        int i; unsigned int sz, es; char nm[64];
        if (sscanf(line, "mtd%d: %x %x \"%63[^\"]\"", &i, &sz, &es, nm) != 4)
            continue;
        parts[nparts].idx  = i;
        parts[nparts].base = base;
        parts[nparts].size = sz;
        snprintf(parts[nparts].name, sizeof parts[nparts].name, "%s", nm);
        base += sz;
        nparts++;
    }
    fclose(f);
    printf("[map] %d partitions, %lu KB total\n", nparts, base / 1024);
    for (int i = 0; i < nparts; i++)
        printf("[map]   mtd%d  0x%06lx..0x%06lx  %s\n",
               parts[i].idx, parts[i].base, parts[i].base + parts[i].size,
               parts[i].name);
    return nparts ? 0 : -1;
}

/*
 * Write `len` bytes to absolute flash offset `off`, splitting the write across
 * whatever partitions cover that range, then read every slice back and compare
 * against the buffer we hold. Nothing here trusts a write it has not read back.
 *
 * /dev/mtdblockN does read-modify-write around the erase blocks and is the only
 * method that verified byte-exact on this NOR; the raw char device is about
 * twice as fast and corrupts.
 */
static int flash_abs(const char *what, unsigned long off,
                     const unsigned char *img, unsigned long len)
{
    printf("[flash] %s: %lu bytes at 0x%06lx\n", what, len, off);

    unsigned long done = 0;
    while (done < len) {
        unsigned long cur = off + done;
        int p = -1;
        for (int i = 0; i < nparts; i++)
            if (cur >= parts[i].base && cur < parts[i].base + parts[i].size) { p = i; break; }
        if (p < 0) { printf("\n!! offset 0x%06lx is outside the flash map\n", cur); return -1; }

        unsigned long in_part = cur - parts[p].base;
        unsigned long room    = parts[p].size - in_part;
        unsigned long slice   = len - done; if (slice > room) slice = room;

        char dev[32];
        snprintf(dev, sizeof dev, "/dev/mtdblock%d", parts[p].idx);
        printf("[flash]   %s + 0x%lx  <- %lu KB (%s)\n",
               dev, in_part, slice / 1024, parts[p].name);

        int fd = open(dev, O_RDWR);
        if (fd < 0) { perror(dev); return -1; }
        if (lseek(fd, in_part, SEEK_SET) != (off_t)in_part) { perror("lseek"); close(fd); return -1; }

        unsigned long w = 0;
        while (w < slice) {
            unsigned long n = slice - w; if (n > CHUNK) n = CHUNK;
            long r = write(fd, img + done + w, n);
            if (r != (long)n) {
                printf("\n!! short write at 0x%06lx: %s\n", cur + w, strerror(errno));
                close(fd); return -1;
            }
            w += n;
            printf("\r[flash]   %lu/%lu KB", w / 1024, slice / 1024);
            fflush(stdout);
        }
        fsync(fd);
        printf("\r[flash]   %lu KB written, verifying\n", slice / 1024);

        if (lseek(fd, in_part, SEEK_SET) != (off_t)in_part) { perror("lseek"); close(fd); return -1; }
        unsigned char *rb = malloc(CHUNK);
        if (!rb) { printf("!! out of memory\n"); close(fd); return -1; }
        unsigned long v = 0;
        while (v < slice) {
            unsigned long n = slice - v; if (n > CHUNK) n = CHUNK;
            long r = read(fd, rb, n);
            if (r != (long)n) { printf("!! short read at 0x%06lx\n", cur + v); free(rb); close(fd); return -1; }
            if (memcmp(rb, img + done + v, n)) {
                printf("!! VERIFY MISMATCH at absolute 0x%06lx\n", cur + v);
                free(rb); close(fd); return -1;
            }
            v += n;
        }
        free(rb);
        close(fd);
        done += slice;
    }
    printf("[flash] %s verified OK\n", what);
    return 0;
}


/* Read `len` bytes from absolute flash offset `off`, spanning partitions the
 * same way flash_abs() writes them. */
static int read_abs(unsigned long off, unsigned char *buf, unsigned long len)
{
    unsigned long done = 0;
    while (done < len) {
        unsigned long cur = off + done;
        int p = -1;
        for (int i = 0; i < nparts; i++)
            if (cur >= parts[i].base && cur < parts[i].base + parts[i].size) { p = i; break; }
        if (p < 0) return -1;
        unsigned long in_part = cur - parts[p].base;
        unsigned long room    = parts[p].size - in_part;
        unsigned long slice   = len - done; if (slice > room) slice = room;
        char dev[32];
        snprintf(dev, sizeof dev, "/dev/mtdblock%d", parts[p].idx);
        int fd = open(dev, O_RDONLY);
        if (fd < 0) return -1;
        if (lseek(fd, in_part, SEEK_SET) != (off_t)in_part) { close(fd); return -1; }
        unsigned long got = 0;
        while (got < slice) {
            long r = read(fd, buf + done + got, slice - got);
            if (r <= 0) { close(fd); return -1; }
            got += r;
        }
        close(fd);
        done += slice;
    }
    return 0;
}

static void env_get(const unsigned char *env, const char *key, char *out, int outsz)
{
    const unsigned char *p = env + 4;
    const unsigned char *lim = env + ENV_SIZE;
    while (p < lim && *p && *p != 0xff) {
        const char *entry = (const char *)p;
        int n = strlen(entry);
        const char *eq = strchr(entry, '=');
        if (eq) {
            int klen = eq - entry;
            if ((int)strlen(key) == klen && !strncmp(entry, key, klen)) {
                snprintf(out, outsz, "%s", eq + 1);
                return;
            }
        }
        p += n + 1;
    }
}

/*
 * Pull our addressing out of the U-Boot environment. The host tool put it there
 * using the standard U-Boot names, so nothing here is invented except the port.
 */
static void load_cfg(void)
{
    unsigned char *env = malloc(ENV_SIZE);
    if (!env) return;
    if (read_abs(OFF_ENV, env, ENV_SIZE) < 0) {
        printf("[cfg] cannot read the env sector; using built-in defaults\n");
        free(env); return;
    }
    unsigned long stored = (unsigned long)env[0] | ((unsigned long)env[1] << 8) |
                           ((unsigned long)env[2] << 16) | ((unsigned long)env[3] << 24);
    if (crc32b(env + 4, ENV_SIZE - 4) != stored) {
        printf("[cfg] env sector fails its own CRC; using built-in defaults\n");
        free(env); return;
    }
    char port[12] = "";
    env_get(env, "ipaddr",       cfg_ip,   sizeof cfg_ip);
    env_get(env, "netmask",      cfg_mask, sizeof cfg_mask);
    env_get(env, "gatewayip",    cfg_gw,   sizeof cfg_gw);
    env_get(env, "serverip",     cfg_srv,  sizeof cfg_srv);
    env_get(env, "fhflash_port", port,     sizeof port);
    if (port[0]) cfg_port = atoi(port);
    printf("[cfg] from flash env: ip=%s mask=%s gw=%s srv=%s port=%d\n",
           cfg_ip, cfg_mask, cfg_gw[0] ? cfg_gw : "(none)", cfg_srv, cfg_port);
    free(env);
}

/* ---- network --------------------------------------------------------- */

static int net_up(void)
{
    struct ifreq ifr;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return -1; }

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, IFNAME, IFNAMSIZ - 1);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(cfg_ip);
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0) { perror("SIOCSIFADDR"); close(s); return -1; }
    sin->sin_addr.s_addr = inet_addr(cfg_mask);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) { perror("SIOCSIFNETMASK"); close(s); return -1; }
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) { perror("SIOCGIFFLAGS"); close(s); return -1; }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) { perror("SIOCSIFFLAGS"); close(s); return -1; }
    /* The TFTP host may be on another subnet (the camera sits on the LAN while
     * the server runs on a different interface), so install a default route.
     * SIOCADDRT rather than netlink -- RTM_GETLINK oopses this kernel. */
    if (cfg_gw[0]) {
        struct rtentry rt;
        memset(&rt, 0, sizeof rt);
        struct sockaddr_in *g = (struct sockaddr_in *)&rt.rt_gateway;
        struct sockaddr_in *d = (struct sockaddr_in *)&rt.rt_dst;
        struct sockaddr_in *m = (struct sockaddr_in *)&rt.rt_genmask;
        g->sin_family = AF_INET; g->sin_addr.s_addr = inet_addr(cfg_gw);
        d->sin_family = AF_INET; d->sin_addr.s_addr = 0;
        m->sin_family = AF_INET; m->sin_addr.s_addr = 0;
        rt.rt_flags = RTF_UP | RTF_GATEWAY;
        rt.rt_dev = (char *)IFNAME;
        if (ioctl(s, SIOCADDRT, &rt) < 0)
            perror("SIOCADDRT (default route)");
        else
            printf("[net] default route via %s\n", cfg_gw);
    }

    close(s);
    printf("[net] %s = %s mask %s, server %s:%d\n",
           IFNAME, cfg_ip, cfg_mask, cfg_srv, cfg_port);
    return 0;
}

/* Minimal RFC 1350 read. Plain 512-byte blocks: far less to get wrong than
 * option negotiation, and it rides out the PHY still auto-negotiating. */
static long tftp_get(const char *name, unsigned char *buf, long cap)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in srv, from;
    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port = htons(cfg_port);
    srv.sin_addr.s_addr = inet_addr(cfg_srv);

    unsigned char req[600];
    int rl = 0;
    req[rl++] = 0; req[rl++] = 1;
    rl += sprintf((char *)req + rl, "%s", name) + 1;
    rl += sprintf((char *)req + rl, "octet") + 1;

    long got = 0;
    int block = 1, tries = 0, started = 0;
    while (1) {
        if (!started && sendto(s, req, rl, 0, (struct sockaddr *)&srv, sizeof srv) < 0) {
            perror("sendto"); close(s); return -1;
        }
        unsigned char pkt[BLK + 4];
        socklen_t fl = sizeof from;
        int n = recvfrom(s, pkt, sizeof pkt, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            if (++tries > 30) { printf("[tftp] %s: timeout\n", name); close(s); return -1; }
            if (!started) { sleep(1); continue; }
            unsigned char a[4] = { 0, 4, (block - 1) >> 8, (block - 1) & 0xFF };
            sendto(s, a, 4, 0, (struct sockaddr *)&from, fl);
            continue;
        }
        tries = 0;
        if (n < 4) continue;
        if (pkt[1] == 5) { printf("[tftp] %s: server error: %s\n", name, pkt + 4); close(s); return -1; }
        if (pkt[1] != 3) continue;

        int b = (pkt[2] << 8) | pkt[3];
        if (b != (block & 0xFFFF)) {
            unsigned char a[4] = { 0, 4, pkt[2], pkt[3] };
            sendto(s, a, 4, 0, (struct sockaddr *)&from, fl);
            continue;
        }
        started = 1;
        srv = from;

        int dl = n - 4;
        if (got + dl > cap) { printf("[tftp] %s: larger than expected\n", name); close(s); return -1; }
        memcpy(buf + got, pkt + 4, dl);
        got += dl;

        unsigned char a[4] = { 0, 4, pkt[2], pkt[3] };
        sendto(s, a, 4, 0, (struct sockaddr *)&from, fl);

        if (dl < BLK) break;
        block++;
        if ((block & 0x3FF) == 0) { printf("\r[tftp] %s: %ld KB", name, got / 1024); fflush(stdout); }
    }
    close(s);
    printf("\r[tftp] %s: %ld bytes\n", name, got);
    return got;
}

/* One full attempt: fetch, gate on CRC, write, verify. Buffers are owned by
 * main() and reused, so a retry cannot leak 5.6 MB into a 32 MB box. */
static int do_flash(unsigned char *rootfs, unsigned char *kernel, unsigned char *env)
{
    load_cfg();
    if (net_up() < 0) { printf("!! network setup failed\n"); return -1; }

    if (tftp_get(IMG_ROOTFS_NAME, rootfs, IMG_ROOTFS_SIZE) != IMG_ROOTFS_SIZE) return -1;
    if (tftp_get(IMG_KERNEL_NAME, kernel, IMG_KERNEL_SIZE) != IMG_KERNEL_SIZE) return -1;
    if (tftp_get(IMG_ENV_NAME,    env,    ENV_SIZE)        != (long)ENV_SIZE)  return -1;

    unsigned long cr = crc32b(rootfs, IMG_ROOTFS_SIZE);
    unsigned long ck = crc32b(kernel, IMG_KERNEL_SIZE);
    printf("[crc] rootfs %08lx (want %08lx)\n", cr, (unsigned long)IMG_ROOTFS_CRC);
    printf("[crc] kernel %08lx (want %08lx)\n", ck, (unsigned long)IMG_KERNEL_CRC);
    if (cr != IMG_ROOTFS_CRC || ck != IMG_KERNEL_CRC) {
        printf("!! CRC mismatch - refusing to write anything\n");
        return -1;
    }

    /* The U-Boot environment carries its own crc32 over the payload, so it
     * validates itself -- no baked-in constant, which keeps one flasher image
     * usable for any camera (the env differs per unit by ethaddr). */
    unsigned long env_stored = (unsigned long)env[0] | ((unsigned long)env[1] << 8) |
                               ((unsigned long)env[2] << 16) | ((unsigned long)env[3] << 24);
    unsigned long env_calc = crc32b(env + 4, ENV_SIZE - 4);
    printf("[crc] env    %08lx (self-declared %08lx)\n", env_calc, env_stored);
    if (env_calc != env_stored) {
        printf("!! env image is not a valid U-Boot environment - refusing to write\n");
        return -1;
    }
    for (unsigned long i = 4; i < ENV_SIZE - 9; i++)
        if (!memcmp(env + i, "bootargs=", 9)) { printf("[env] %.180s\n", env + i); break; }

    /* rootfs, then kernel, then env: the env is the smallest write and the one
     * that commits the switch, so it sits in the shortest risk window. */
    if (flash_abs("rootfs", OFF_ROOTFS, rootfs, IMG_ROOTFS_SIZE) < 0) return -1;
    if (flash_abs("kernel", OFF_KERNEL, kernel, IMG_KERNEL_SIZE) < 0) return -1;
    if (flash_abs("env",    OFF_ENV,    env,    ENV_SIZE)        < 0) return -1;
    return 0;
}

int main(void)
{
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);
    /* CONFIG_DEVTMPFS_MOUNT does not cover initramfs, so mount it ourselves. */
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);

    int c = open("/dev/console", O_RDWR);
    if (c >= 0) { dup2(c, 0); dup2(c, 1); dup2(c, 2); if (c > 2) close(c); }
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\n=== OpenIPC network flasher (FH8856) ===\n");
    crc_init();
    if (read_mtd_table() < 0) { printf("!! cannot read the flash map\n"); while (1) sleep(1); }

    unsigned char *rootfs = malloc(IMG_ROOTFS_SIZE);
    unsigned char *kernel = malloc(IMG_KERNEL_SIZE);
    unsigned char *env    = malloc(ENV_SIZE);
    if (!rootfs || !kernel || !env) { printf("!! out of memory\n"); while (1) sleep(1); }

    /*
     * Retry forever rather than halting. By the time this runs the vendor
     * kernel is gone, so a halt would strand the camera until someone power
     * cycles it by hand -- and this has to work on a camera nobody can reach.
     * Every failure here is transient from the box's point of view (server
     * down, link not up yet, a bad transfer), and nothing is written unless
     * the CRC gate passes first, so retrying is always safe. The watchdog
     * stays fed by the kernel because we never open it, so the box survives an
     * arbitrarily long wait for the server to come back.
     */
    for (int attempt = 1; ; attempt++) {
        printf("\n--- attempt %d ---\n", attempt);
        if (do_flash(rootfs, kernel, env) == 0) {
            sync();
            printf("\n=== flash complete and verified - rebooting into OpenIPC ===\n");
            sleep(2);
            reboot(RB_AUTOBOOT);
        }
        printf("\n!! attempt %d did not complete; retrying in 15s\n", attempt);
        printf("!! (nothing is written unless every image passes its CRC first)\n");
        sleep(15);
    }
    return 1;
}
