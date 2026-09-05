#!/usr/bin/env python3
"""
asecam-flash -- convert an Asecam / Vatilon PB1 camera (Fullhan FH8856 V100)
from stock vendor firmware to OpenIPC + divinus, over the network. No UART, no
disassembly.

    python3 asecam-flash.py identify <ip>     what is it, and is it supported
    python3 asecam-flash.py backup   <ip>     dump all six flash partitions
    python3 asecam-flash.py flash    <ip>     identify -> backup -> flash -> verify

Everything needed is in images/. Building the firmware yourself is optional --
see the repository links in README.md.

How it works, briefly. The rootfs cannot be written from the running vendor
system: it lives in mtd2, so overwriting it kills `ipcam`, which holds the
watchdog, and the board resets ~32 s later -- against the ~42 s that 3.1 MB
needs at the only byte-exact write speed. Unwinnable. So the vendor side writes
exactly one thing, a kernel carrying a small initramfs flasher, and that flasher
does the rest from RAM where nothing holds the watchdog and there is no
deadline.
"""
import argparse, hashlib, os, re, socket, struct, sys, threading, time, zlib

try:
    import pexpect
except ImportError:
    sys.exit("!! needs pexpect:  pip install pexpect   (or: apt install python3-pexpect)")

HERE     = os.path.dirname(os.path.abspath(__file__))
IMAGES   = os.path.join(HERE, "images")
BACKUPS  = os.path.join(HERE, "backups")
PORT     = 6969

FLASHER  = "uImage.flasher"
KERNEL   = "uImage.fh8856v100"
ROOTFS   = "rootfs.squashfs.fh8856v100"
ENVNAME  = "env.bin"

VENDOR_PORT = 2360
VENDOR_USER, VENDOR_PASS = "root", "ipc@hs66"
WEB_PORT = 8080

DEV_KERNEL_PART = "/dev/mtdblock1"          # vendor "kernel" partition
ENV_OFF, ENV_SIZE = 0x40000, 0x10000
OPENIPC_SLOT_KERNEL, OPENIPC_SLOT_ROOTFS = 0x200000, 0x500000
PLACEHOLDER_MAC = "10:20:30:40:50:60"

SUPPORTED_PLAT = 0x17092901
PKG_TO_CHIP = {0xC: ("FH8852", 512), 0xD: ("FH8856", 1024)}
VENDOR_MTD = [("uboot", 0x050000), ("kernel", 0x280000), ("appfs", 0x400000),
              ("custom", 0x0d0000), ("config", 0x050000), ("data", 0x010000)]
MTD_FILES = ["uboot", "kernel", "appfs", "custom", "config", "data"]

MTD = ("mtdparts=spi_flash:256k(boot),64k(env),2048k(kernel),"
       "5120k(rootfs),-(rootfs_data)")
BOOTARGS = ("mem=32M console=ttyS0,115200 root=/dev/mtdblock3 init=/init "
            "rootfstype=squashfs " + MTD)
# `sleep 5` first: it IS Ctrl-C interruptible even though the autoboot countdown
# is not, so every later boot has a guaranteed way back into U-Boot over serial.
BOOTCMD = ("sleep 5;bootupdate;sf probe 0;"
           "sf read 0xa1000000 0x50000 0x280000;bootm 0xa1000000")

DISC_REQ, DISC_RSP = b"FHFLASH-REQ v1", "FHFLASH-CFG v1"


def say(msg=""):   print(msg, flush=True)
def step(msg):     say("\n== %s" % msg)
def ok(msg):       say("   [ok]   %s" % msg)
def bad(msg):      say("   [FAIL] %s" % msg)
def warn(msg):     say("   [warn] %s" % msg)


# --------------------------------------------------------------------------
# built-in server: TFTP (read+write) and the flasher's config discovery, on one
# UDP port so the user needs at most one firewall rule
# --------------------------------------------------------------------------
class Server(threading.Thread):
    def __init__(self, serve_dir, out_dir, cfg=None, port=PORT):
        super().__init__(daemon=True)
        self.dir, self.out, self.port = serve_dir, out_dir, port
        self.cfg, self.log, self.stop = cfg, [], False
        os.makedirs(out_dir, exist_ok=True)

    def note(self, m):
        self.log.append(m); say("   [srv]  %s" % m)

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("0.0.0.0", self.port)); s.settimeout(1.0)
        self.sock = s
        while not self.stop:
            try:
                req, peer = s.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if req.startswith(DISC_REQ):
                self.answer_discovery(s, peer)
            elif len(req) >= 4 and req[1] in (1, 2):
                threading.Thread(target=self.transfer, args=(req, peer), daemon=True).start()

    def answer_discovery(self, s, peer):
        if not self.cfg:
            return
        msg = ("%s ip=%s mask=%s gw=%s srv=%s port=%d"
               % (DISC_RSP, self.cfg["ip"], self.cfg["mask"],
                  self.cfg.get("gw", ""), self.cfg["srv"], self.port))
        # Broadcast the reply: the camera has no address yet, so a unicast
        # answer would have nowhere to land.
        s.sendto(msg.encode(), ("255.255.255.255", self.port))
        self.note("flasher asked for config -> %s" % self.cfg["ip"])

    def transfer(self, req, peer):
        op = req[1]
        name = os.path.basename(req[2:].split(b"\x00")[0].decode("latin-1", "replace"))
        d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        d.bind(("0.0.0.0", 0)); d.settimeout(5)
        try:
            if op == 1:
                self.send_file(d, peer, name)
            else:
                self.recv_file(d, peer, name)
        finally:
            d.close()

    def send_file(self, d, peer, name):
        path = os.path.join(self.dir, name)
        if not os.path.isfile(path):
            d.sendto(b"\x00\x05\x00\x01not found\x00", peer)
            self.note("GET %s -> NOT FOUND" % name); return
        data = open(path, "rb").read()
        self.note("GET %s (%d bytes)" % (name, len(data)))
        blk, off = 1, 0
        while True:
            chunk = data[off:off + 512]
            pkt = b"\x00\x03" + struct.pack(">H", blk & 0xFFFF) + chunk
            for _ in range(6):
                d.sendto(pkt, peer)
                try:
                    a, _ = d.recvfrom(64)
                except socket.timeout:
                    continue
                if len(a) >= 4 and a[1] == 4 and struct.unpack(">H", a[2:4])[0] == (blk & 0xFFFF):
                    break
            else:
                self.note("GET %s aborted at block %d" % (name, blk)); return
            off += len(chunk); blk += 1
            if len(chunk) < 512:
                break
        self.note("GET %s done" % name)

    def recv_file(self, d, peer, name):
        d.sendto(b"\x00\x04\x00\x00", peer)
        data, want = b"", 1
        while True:
            try:
                pkt, addr = d.recvfrom(600)
            except socket.timeout:
                break
            if len(pkt) < 4 or pkt[1] != 3:
                break
            n = struct.unpack(">H", pkt[2:4])[0]
            if n == (want & 0xFFFF):
                data += pkt[4:]; want += 1
            d.sendto(b"\x00\x04" + pkt[2:4], addr)
            if len(pkt) - 4 < 512:
                break
        open(os.path.join(self.out, name), "wb").write(data)
        self.note("PUT %s (%d bytes)" % (name, len(data)))


# --------------------------------------------------------------------------
# camera session
# --------------------------------------------------------------------------
class Cam:
    def __init__(self, ip):
        self.ip = ip
        self.c = pexpect.spawn("telnet %s %d" % (ip, VENDOR_PORT),
                               encoding="latin-1", timeout=60)
        try:
            self.c.expect("login:");   self.c.sendline(VENDOR_USER)
            self.c.expect("assword:"); self.c.sendline(VENDOR_PASS)
            self.c.expect(r"[#$] ")
        except Exception:
            raise RuntimeError("no vendor root shell on %s:%d" % (ip, VENDOR_PORT))

    def run(self, cmd, timeout=60):
        self.c.sendline(cmd + ' ; echo __EO"C"__')
        self.c.expect("__EOC__", timeout=timeout)
        out = self.c.before.replace("\r", "")
        self.c.expect(r"[#$] ", timeout=timeout)
        return "\n".join(out.split("\n")[1:])

    def close(self):
        try: self.c.sendline("exit")
        except Exception: pass


def port_open(ip, port, t=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(t)
    try:    return s.connect_ex((ip, port)) == 0
    finally: s.close()


def host_ip_for(cam_ip):
    """Which of our addresses the camera would reply to."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((cam_ip, 9)); return s.getsockname()[0]
    finally:
        s.close()


def parse_mtd(text):
    got = re.findall(r'mtd(\d+):\s+([0-9a-f]{8})\s+[0-9a-f]{8}\s+"([^"]+)"', text)
    return [(nm, int(sz, 16)) for _i, sz, nm in got]


def decode_chip(plat, pkg):
    if plat == SUPPORTED_PLAT:
        chip, ddr = PKG_TO_CHIP.get(pkg & 0xF, (None, None))
        if chip:
            return chip, ddr, True, "V100 generation (plat 0x%08x, pkg nibble 0x%X)" % (plat, pkg & 0xF)
        return None, None, False, "plat is V100 but pkg nibble 0x%X is unknown" % (pkg & 0xF)
    if plat == 0x19112201:
        return ("FH8856V200", None, False,
                "V200 generation -- different silicon; this firmware targets V100 "
                "and a V200 build hangs on this board")
    return None, None, False, "unknown platform id 0x%08x" % plat


def gather(cam):
    info = {}
    chip = cam.run("cat /proc/driver/chip")
    for k, pat in (("plat_id", r"plat_id\s*:?\s*(0x[0-9a-fA-F]+)"),
                   ("pkg_id",  r"pkg_id\s*:?\s*(0x[0-9a-fA-F]+)"),
                   ("chip_name", r"chip_name\s*:?\s*(\S+)")):
        m = re.search(pat, chip)
        if m: info[k] = m.group(1)
    info["mtd"] = parse_mtd(cam.run("cat /proc/mtd"))
    ifc = cam.run("ifconfig eth0")
    m = re.search(r"HWaddr\s+([0-9A-Fa-f:]{17})", ifc); info["mac"] = m.group(1) if m else ""
    m = re.search(r"inet addr:(\S+)", ifc);             info["ip"]  = m.group(1) if m else ""
    m = re.search(r"Mask:(\S+)", ifc);                  info["mask"] = m.group(1) if m else "255.255.255.0"
    m = re.search(r"^0\.0\.0\.0\s+(\S+)", cam.run("route -n"), re.M)
    info["gw"] = m.group(1) if m else ""
    return info


def verdict(info):
    plat = int(info.get("plat_id", "0"), 16)
    pkg  = int(info.get("pkg_id", "0"), 16)
    chip, ddr, sup, why = decode_chip(plat, pkg)
    layout_ok = info.get("mtd") == VENDOR_MTD
    say("   SoC        %s" % (info.get("chip_name") or "?"))
    say("   decode     %s" % why)
    say("   MAC        %s%s" % (info.get("mac") or "?",
                                "   *** placeholder ***" if info.get("mac", "").upper() == PLACEHOLDER_MAC else ""))
    say("   flash map  %s" % ("stock vendor layout, 8 MiB" if layout_ok else "UNRECOGNISED"))
    return (sup and layout_ok), chip


# --------------------------------------------------------------------------
def cmd_identify(a):
    if not port_open(a.ip, VENDOR_PORT):
        if port_open(a.ip, WEB_PORT):
            say("\n%s is ALREADY CONVERTED (divinus on :%d; the vendor telnet "
                "backdoor on :%d is gone)." % (a.ip, WEB_PORT, VENDOR_PORT))
            return 0
        say("\nNothing answered on tcp/%d or tcp/%d." % (VENDOR_PORT, WEB_PORT))
        say("Stock firmware needs a DHCP server to get an address at all -- it has")
        say("no static fallback. Give it one, then try again.")
        return 2
    cam = Cam(a.ip)
    try:
        step("identifying %s" % a.ip)
        info = gather(cam)
        good, chip = verdict(info)
    finally:
        cam.close()
    say("")
    if good:
        say("VERDICT: SUPPORTED -- stock %s (V100). Next: backup." % chip)
        return 0
    say("VERDICT: NOT SUPPORTED. Do not flash.")
    return 1


def cmd_backup(a, cam=None, info=None):
    close_after = cam is None
    if cam is None:
        cam = Cam(a.ip); info = gather(cam)
    tag = a.name or (info.get("mac", "").replace(":", "") or a.ip.replace(".", "_"))
    dest = os.path.join(BACKUPS, tag)
    os.makedirs(dest, exist_ok=True)

    step("backing up all six partitions -> %s" % dest)
    say("   These hold per-unit serials, calibration and keys. They are NOT")
    say("   interchangeable between cameras and cannot be re-downloaded.")
    srv = Server(IMAGES, dest, port=a.port)
    srv.start(); time.sleep(0.3)
    host = host_ip_for(a.ip)
    try:
        for i, nm in enumerate(MTD_FILES):
            fn = "%s_mtd%d_%s.bin" % (tag, i, nm)
            want = dict(VENDOR_MTD)[nm] if info.get("mtd") == VENDOR_MTD else None
            say("   mtd%d %-7s ..." % (i, nm))
            _stale = os.path.join(dest, fn)
            if os.path.exists(_stale): os.remove(_stale)
            cam.run("tftp -p -l /dev/mtdblock%d -r %s %s %d > /dev/null 2>&1"
                    % (i, fn, host, a.port), timeout=900)
            p = os.path.join(dest, fn)
            got = os.path.getsize(p) if os.path.exists(p) else 0
            if want and got != want:
                bad("mtd%d is %d bytes, expected %d -- TRUNCATED" % (i, got, want))
                return 1
            ok("mtd%d %-7s %d bytes" % (i, nm, got))
    finally:
        srv.stop = True
        if close_after: cam.close()

    with open(os.path.join(dest, "MD5SUMS"), "w") as f:
        for fn in sorted(os.listdir(dest)):
            if fn.endswith(".bin"):
                h = hashlib.md5(open(os.path.join(dest, fn), "rb").read()).hexdigest()
                f.write("%s  %s\n" % (h, fn))
    ok("checksums written to %s/MD5SUMS" % dest)
    say("\n   Keep this directory. It is the only way back to stock for THIS camera.")
    return 0, dest


def build_env(uboot_backup, ethaddr, ipaddr=None):
    """Build the new U-Boot environment from THIS camera's own stock one.

    Starting from the camera's real environment (rather than a canned copy)
    keeps every key U-Boot actually uses -- phymode, bootdelay, ethact, the
    console keys -- and only replaces what the conversion has to change.
    """
    blob = open(uboot_backup, "rb").read()[ENV_OFF:ENV_OFF + ENV_SIZE]
    if len(blob) != ENV_SIZE:
        raise RuntimeError("uboot backup too short to contain the env sector")
    if zlib.crc32(blob[4:]) & 0xFFFFFFFF != int.from_bytes(blob[:4], "little"):
        raise RuntimeError("the camera's stock env failed its own CRC")
    env = {}
    for item in blob[4:].split(b"\x00"):
        if not item or item.startswith(b"\xff"):
            break
        k, _, v = item.partition(b"=")
        env[k.decode("latin-1")] = v.decode("latin-1")
    env["bootargs"], env["bootcmd"] = BOOTARGS, BOOTCMD
    if ethaddr: env["ethaddr"] = ethaddr
    if ipaddr:  env["ipaddr"]  = ipaddr
    payload = b"".join(("%s=%s" % kv).encode() + b"\x00" for kv in sorted(env.items())) + b"\x00"
    payload += b"\xff" * (ENV_SIZE - 4 - len(payload))
    return (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little") + payload, env


def build_boot_env(uboot_backup, cfg):
    """Env for the FLASHER's boot: stock bootargs/bootcmd kept exactly as they
    are, with only the addressing added.

    Keeping the vendor boot settings is the safety property. This sector is
    written before the kernel, so if the kernel write then fails the camera
    still boots stock firmware exactly as before -- ipaddr/netmask/gatewayip/
    serverip are read by U-Boot only, and the vendor's Linux uses udhcpc.
    """
    blob = open(uboot_backup, "rb").read()[ENV_OFF:ENV_OFF + ENV_SIZE]
    if zlib.crc32(blob[4:]) & 0xFFFFFFFF != int.from_bytes(blob[:4], "little"):
        raise RuntimeError("the camera's stock env failed its own CRC")
    env = {}
    for item in blob[4:].split(b"\x00"):
        if not item or item.startswith(b"\xff"):
            break
        k, _, v = item.partition(b"=")
        env[k.decode("latin-1")] = v.decode("latin-1")
    env["ipaddr"]       = cfg["ip"]
    env["netmask"]      = cfg["mask"]
    env["serverip"]     = cfg["srv"]
    env["fhflash_port"] = str(cfg["port"])
    if cfg.get("gw"):
        env["gatewayip"] = cfg["gw"]
    payload = b"".join(("%s=%s" % kv).encode() + b"\x00" for kv in sorted(env.items())) + b"\x00"
    payload += b"\xff" * (ENV_SIZE - 4 - len(payload))
    return (zlib.crc32(payload) & 0xFFFFFFFF).to_bytes(4, "little") + payload, env


def uimage_ok(path):
    d = open(path, "rb").read()
    if len(d) < 64: return None
    magic, hcrc, _t, size, _l, _e, dcrc = struct.unpack(">IIIIIII", d[:28])
    if magic != 0x27051956: return None
    hdr = bytearray(d[:64]); hdr[4:8] = b"\0\0\0\0"
    if zlib.crc32(bytes(hdr)) & 0xFFFFFFFF != hcrc: return None
    if zlib.crc32(d[64:64 + size]) & 0xFFFFFFFF != dcrc: return None
    return len(d)


def cmd_flash(a):
    if not port_open(a.ip, VENDOR_PORT):
        if port_open(a.ip, WEB_PORT):
            say("%s is already converted -- nothing to do." % a.ip); return 0
        say("No vendor shell on %s:%d." % (a.ip, VENDOR_PORT)); return 2

    cam = Cam(a.ip)
    try:
        step("1/7  identify")
        info = gather(cam)
        good, chip = verdict(info)
        if not good:
            say("\nNOT SUPPORTED -- refusing to flash."); return 1
        ok("supported: stock %s (V100)" % chip)

        step("2/7  images")
        for nm, slot in ((FLASHER, 0x280000), (KERNEL, OPENIPC_SLOT_KERNEL)):
            p = os.path.join(IMAGES, nm)
            sz = uimage_ok(p) if os.path.isfile(p) else None
            if not sz:  bad("%s missing or not a valid uImage" % nm); return 1
            if sz > slot: bad("%s does not fit its slot" % nm); return 1
            ok("%s %d bytes, CRCs valid" % (nm, sz))
        rp = os.path.join(IMAGES, ROOTFS)
        if not os.path.isfile(rp) or os.path.getsize(rp) > OPENIPC_SLOT_ROOTFS:
            bad("%s missing or too large" % ROOTFS); return 1
        ok("%s %d bytes" % (ROOTFS, os.path.getsize(rp)))

        step("3/7  backup (required before any write)")
        r = cmd_backup(a, cam, info)
        if isinstance(r, int): return r
        _, dest = r

        step("4/7  environment, built from this camera's own stock env")
        ub = os.path.join(dest, [f for f in os.listdir(dest) if "_mtd0_" in f][0])
        mac = info.get("mac", "")
        if not mac or mac.upper() == PLACEHOLDER_MAC:
            warn("camera reports the placeholder MAC; the converted unit would take a")
            warn("random MAC each boot. Pass --ethaddr to set the real one.")
            if not a.ethaddr:
                bad("refusing to continue without --ethaddr"); return 1
        # Default the no-DHCP fallback to the address the camera has right now.
        # Otherwise a converted camera on a network without DHCP reappears at
        # whatever the vendor env happened to hold, not where you left it.
        img, env = build_env(ub, a.ethaddr or mac, a.ipaddr or info.get("ip"))
        os.makedirs(os.path.join(HERE, ".stage"), exist_ok=True)
        for nm in (FLASHER, KERNEL, ROOTFS):
            src, dst = os.path.join(IMAGES, nm), os.path.join(HERE, ".stage", nm)
            if not os.path.exists(dst) or open(dst, "rb").read() != open(src, "rb").read():
                open(dst, "wb").write(open(src, "rb").read())
        open(os.path.join(HERE, ".stage", ENVNAME), "wb").write(img)
        ok("ethaddr %s" % env["ethaddr"])
        ok("no-DHCP fallback address %s" % env.get("ipaddr", "?"))
        ok("bootcmd starts with 'sleep 5' (keeps a serial rescue window forever)")

        host = host_ip_for(a.ip)
        cfg = {"ip": info["ip"], "mask": info["mask"], "gw": info.get("gw", ""),
               "srv": host, "port": a.port}
        srv = Server(os.path.join(HERE, ".stage"), os.path.join(HERE, ".stage", "up"),
                     cfg=cfg, port=a.port)
        srv.start(); time.sleep(0.3)

        step("5/7  network check -- BOTH directions, with a real transfer")
        say("   (ping is not enough: on a segmented network the camera->host")
        say("    direction is often the blocked one, and ping still succeeds)")
        probe = os.urandom(2048)
        open(os.path.join(HERE, ".stage", "probe.bin"), "wb").write(probe)
        cam.run("rm -f /tmp/probe.bin", 30)
        cam.run("tftp -g -r probe.bin -l /tmp/probe.bin %s %d > /dev/null 2>&1" % (host, a.port), 60)
        got = cam.run("wc -c < /tmp/probe.bin 2>/dev/null || echo 0", 30).strip().split()[-1]
        if got != str(len(probe)):
            bad("camera cannot download from %s:%d (got %s bytes)" % (host, a.port, got))
            say("\n   Open UDP %d from %s to %s, then retry." % (a.port, a.ip, host))
            return 1
        ok("camera -> host download works")
        _stale = os.path.join(HERE, ".stage", "up", "probe_up.bin")
        if os.path.exists(_stale): os.remove(_stale)
        cam.run("tftp -p -l /tmp/probe.bin -r probe_up.bin %s %d > /dev/null 2>&1" % (host, a.port), 60)
        up = os.path.join(HERE, ".stage", "up", "probe_up.bin")
        if not (os.path.isfile(up) and open(up, "rb").read() == probe):
            bad("camera cannot upload to %s:%d -- verification would be impossible" % (host, a.port))
            return 1
        ok("camera -> host upload works")
        cam.run("rm -f /tmp/probe.bin", 30)

        step("6/7  write the flasher's addressing into the env sector")
        say("   Stock bootargs/bootcmd are kept byte for byte -- only ipaddr,")
        say("   netmask, serverip (and gatewayip) are added, which U-Boot reads")
        say("   and the vendor's Linux ignores. So if the next step fails, this")
        say("   camera still boots stock firmware exactly as it does now.")
        boot_env, be = build_boot_env(ub, cfg)
        open(os.path.join(HERE, ".stage", "bootenv.bin"), "wb").write(boot_env)
        cam.run("rm -f /tmp/bootenv.bin", 30)
        r = cam.run("tftp -g -r bootenv.bin -l /tmp/bootenv.bin %s %d > /dev/null 2>&1 ; echo rc=$?"
                    % (host, a.port), 120)
        if "rc=0" not in r:
            bad("could not fetch the env image"); return 1
        # seek=4 with bs=64k lands exactly on 0x40000; the U-Boot CODE below it
        # is never touched.
        r = cam.run("dd if=/tmp/bootenv.bin of=/dev/mtdblock0 bs=65536 seek=4 "
                    "conv=notrunc 2>&1 ; sync ; echo rc=$?", 300)
        if "rc=0" not in r:
            bad("env write failed: %s" % r.strip()); return 1
        cam.run("rm -f /tmp/bootenv.bin", 30)
        _stale = os.path.join(HERE, ".stage", "up", "mtd0_after.bin")
        if os.path.exists(_stale): os.remove(_stale)
        cam.run("tftp -p -l /dev/mtdblock0 -r mtd0_after.bin %s %d > /dev/null 2>&1"
                % (host, a.port), 300)
        back = os.path.join(HERE, ".stage", "up", "mtd0_after.bin")
        if not os.path.isfile(back):
            bad("no env read-back"); return 1
        got0 = open(back, "rb").read()
        if got0[ENV_OFF:ENV_OFF + ENV_SIZE] != boot_env:
            bad("env sector did not read back correctly -- NOT continuing"); return 1
        if got0[:ENV_OFF] != open(ub, "rb").read()[:ENV_OFF]:
            bad("U-Boot code changed -- this should be impossible; stopping"); return 1
        ok("env written and verified; U-Boot code untouched")
        ok("flasher will use ip=%s srv=%s:%d" % (be["ipaddr"], be["serverip"], cfg["port"]))

        step("7/7  write the flasher kernel, then verify")
        say("   Streamed straight into %s -- never staged, because the camera has" % DEV_KERNEL_PART)
        say("   ~1.4 MB free in /tmp and ~3.4 MB RAM, and an OOM kill of ipcam")
        say("   would trip the watchdog mid-write.")
        r = cam.run("tftp -g -r %s -l %s %s %d > /dev/null 2>&1 ; echo rc=$?"
                    % (FLASHER, DEV_KERNEL_PART, host, a.port), 900)
        if "rc=0" not in r:
            bad("write failed: %s" % r.strip()); return 1
        cam.run("sync", 60)
        ok("written")

        say("   reading it back for a byte comparison ...")
        _stale = os.path.join(HERE, ".stage", "up", "mtd1_after.bin")
        if os.path.exists(_stale): os.remove(_stale)
        cam.run("tftp -p -l %s -r mtd1_after.bin %s %d > /dev/null 2>&1"
                % (DEV_KERNEL_PART, host, a.port), 900)
        back = os.path.join(HERE, ".stage", "up", "mtd1_after.bin")
        ref = open(os.path.join(IMAGES, FLASHER), "rb").read()
        if not os.path.isfile(back):
            bad("no read-back received -- NOT rebooting"); return 1
        gotb = open(back, "rb").read()
        if len(gotb) < len(ref) or gotb[:len(ref)] != ref:
            bad("read-back does not match -- NOT rebooting. Re-run to rewrite;")
            say("   the vendor system is untouched and still running.")
            return 1
        ok("verified byte-for-byte")

        step("handing over -- rebooting into the flasher")
        say("   From here the flasher owns the camera. It retries forever rather")
        say("   than stranding itself, so leave this running until the camera")
        say("   comes back on OpenIPC.")
        cam.c.sendline("reboot")
        try: cam.c.expect(pexpect.EOF, timeout=30)
        except Exception: pass
    finally:
        try: cam.close()
        except Exception: pass

    deadline = time.time() + 900
    while time.time() < deadline:
        if port_open(a.ip, WEB_PORT, 1) or port_open(a.ip, 22, 1):
            say("\n*** DONE -- %s is running OpenIPC + divinus ***" % a.ip)
            say("    web  http://%s:8080     RTSP rtsp://%s:554" % (a.ip, a.ip))
            say("    The first SSH/serial root login sets the password (openipc-claim).")
            return 0
        time.sleep(5)
    say("\n!! the camera has not come back within 15 minutes.")
    say("   The flasher retries indefinitely -- check the [srv] lines above to see")
    say("   how far it got, and leave this running.")
    return 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=["identify", "backup", "flash"])
    p.add_argument("ip")
    p.add_argument("--port", type=int, default=PORT, help="UDP port for TFTP + discovery")
    p.add_argument("--ethaddr", help="the camera's real MAC, if it reports the placeholder")
    p.add_argument("--ipaddr", help="address the converted camera falls back to with no DHCP")
    p.add_argument("--name", help="backup directory name (default: the camera's MAC)")
    a = p.parse_args()
    try:
        if a.action == "identify": return cmd_identify(a)
        if a.action == "backup":
            r = cmd_backup(a)
            return r if isinstance(r, int) else 0
        return cmd_flash(a)
    except RuntimeError as e:
        say("\n!! %s" % e); return 2
    except KeyboardInterrupt:
        say("\ninterrupted"); return 130


if __name__ == "__main__":
    sys.exit(main())
