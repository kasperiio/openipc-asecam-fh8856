# OpenIPC + divinus for the Asecam 4K IP camera (Fullhan FH8856 V100)

Replaces the stock vendor firmware on an
**[Asecam 4K IP camera](https://www.aliexpress.com/item/1005004210196385.html)**
(Vatilon **PB1** board, Fullhan **FH8856** V100, GalaxyCore GC4653) with
**OpenIPC** running the **divinus** streamer.

**Over the network. No UART, no soldering, no opening the camera.**

Verified end to end on three cameras: RTSP, ONVIF, web UI, snapshots, IR-cut and
day/night all working from flash.

> **About "4K / 8MP".** The listing markets 4K 8MP. The sensor actually fitted to
> this board is a **GC4653, natively 2560×1440 (4 MP)** — that is what the stock
> firmware captures too. If you expected 3840×2160 out of the sensor, that is the
> hardware, not this conversion.

---

## Quick start

Requires Python 3 with `pexpect` (`apt install python3-pexpect`), and the camera
reachable on your network.

```bash
python3 asecam-flash.py identify 192.168.1.50
```
```bash
python3 asecam-flash.py flash 192.168.1.50
```

That is the whole procedure. `flash` runs the full sequence and stops at the
first thing that looks wrong:

1. **identify** — reads the SoC id and flash map; refuses anything that is not a
   supported FH8856/FH8852 **V100** with the stock layout
2. **check images** — validates both kernels by magic, header CRC and payload CRC
3. **back up all six partitions** to `backups/<mac>/`, size-checked, with MD5SUMS
4. **build the environment** from *this camera's own* stock environment
5. **verify the network in both directions** with a real transfer
6. **write, then read back and byte-compare** before it will reboot anything

It serves everything itself over one UDP port (`6969`), so there is no TFTP
server to set up. If a firewall sits between you and the camera, allow **UDP
6969 from the camera to your machine** — the transfers are camera-initiated.

**Not found?** Stock firmware defaults to DHCP and has **no static fallback**, so
with no DHCP server it never gets an address at all. Give the network a DHCP
server, then rerun.

---

## What it is doing, and why

The rootfs cannot be written from the running vendor system. It lives in `mtd2`,
which *is* the running filesystem, so overwriting it kills `ipcam` — which holds
the watchdog — and the board resets about **32 s** later, against the **~42 s**
that 3.1 MB needs at the only write speed that verifies byte-exact (~76 KB/s).
That race is unwinnable, and the watchdog cannot be taken over: `/dev/watchdog`
stays busy even after killing `ipcam`.

But that is a fact about *who holds the watchdog*, not about network flashing.
`fh_wdt` kicks the hardware from a kernel timer whenever nothing has the device
open — so once the vendor userland is gone, **the kernel feeds the watchdog
forever and the write has no deadline**.

So the vendor side writes two things: the addressing, into the U-Boot
environment sector — keeping the stock `bootargs`/`bootcmd` byte for byte, so a
failure after that still boots the stock firmware — and then a kernel carrying a
small initramfs flasher. On reboot that flasher owns the box, reads its
addressing back out of the environment, downloads the real images, and writes
rootfs, kernel and environment — each read back and byte-compared — before
rebooting into OpenIPC. It retries indefinitely rather than stranding a camera
you cannot reach.

---

## Safety

- **The backup is not optional and the tool will not skip it.** `mtd3`/`mtd4`/
  `mtd5` hold per-unit serials, calibration and keys. They are **not**
  interchangeable between cameras and cannot be re-downloaded. `backups/<mac>/`
  is your only way back to stock.
- **Nothing is written until every check passes**, and nothing reboots until the
  written partition has been read back and compared byte for byte.
- Between the write starting and that comparison passing, the camera has no
  valid vendor kernel. An unexpected reboot in that window means recovery needs
  serial access. It is about 25 seconds. The write is freely repeatable as long
  as the camera stays powered — just rerun.
- Stock U-Boot is **never** overwritten, so a camera with serial access is always
  recoverable.

## After conversion

Ports **22** (SSH), **554** (RTSP), **8080** (divinus web). The vendor's telnet
backdoor on **2360** is gone.

The image ships **unclaimed**: the first root login runs `openipc-claim`, which
makes you set a password. divinus streams before you claim, but a shell, SSH and
RTSP need it.

---

## Updating a camera that is already converted

Do not use the flasher for this — the camera already runs OpenIPC, so it has
`sysupgrade`, which pivots to a RAM root before writing and needs no UART, no
TFTP server and no firewall rule:

```bash
scp -O images/uImage.fh8856v100 images/rootfs.squashfs.fh8856v100 root@<camera>:/tmp/
```
```bash
ssh root@<camera> 'sysupgrade --kernel=/tmp/uImage.fh8856v100 --rootfs=/tmp/rootfs.squashfs.fh8856v100'
```

`scp -O` matters: the camera's dropbear has no `sftp-server`, and modern `scp`
speaks SFTP by default.

**Never pass `-n` / `--wipe_overlay`.** It wipes the overlay, which returns the
camera to unclaimed and drops its root password.

If the WebUI has ever saved settings, `/overlay/etc/divinus.yaml` exists and
masks the flashed one, so a config change in a new release will not take effect
until you remove it. Check before assuming an update applied.

---

## Building it yourself

The images in `images/` are prebuilt, so you do not need to. If you want to:

| | |
|---|---|
| divinus + the Fullhan V100 HAL | [`kasperiio/divinus`](https://github.com/kasperiio/divinus) branch **`fullhan-v100`** |
| firmware / buildroot tree | [`kasperiio/firmware`](https://github.com/kasperiio/firmware) branch **`fullhan-fh8856v100-divinus`** |

```bash
git clone -b fullhan-fh8856v100-divinus https://github.com/kasperiio/firmware.git
cd firmware && make BOARD=fh8856v100_lite
```

> **Until the kernel fixes are merged upstream**, that build fetches a kernel
> *without* them and `eth0` will not come up (the JL1101 PHY id is one of the
> fixes). The fixes live on
> [`kasperiio/linux`](https://github.com/kasperiio/linux) branch
> **`fullhan-fh8856v100-board`**; to build now, point the defconfig at it:
>
> ```
> BR2_LINUX_KERNEL_CUSTOM_TARBALL_LOCATION="https://github.com/kasperiio/linux/archive/fullhan-fh8856v100-board.tar.gz"
> ```
>
> in `br-ext-chip-fullhan/configs/fh8856v100_lite_defconfig`. The shipped
> `images/` were built exactly this way and boot-tested.

Both are forks of upstream [OpenIPC](https://github.com/OpenIPC), intended for
upstreaming. The initramfs flasher lives in `initramfs/` in this repository
(`flasher.c` plus `build_flasher.sh`, which needs the buildroot toolchain).

---

## Supported hardware

Supported is plat_id **`0x17092901`** with pkg_id low nibble **`0xD` (FH8856)**
or **`0xC` (FH8852)** — the **V100** generation — with the stock 8 MiB layout.

An **FH8856V200** (plat_id `0x19112201`) is different silicon and is **not**
supported. This matters more than it sounds: built as V200, this board hangs in
`fh_pinctrl_init_devices()` muxing pad 51, misreads PLL2 and corrupts the console
baud, so the failure looks like a dead board. `identify` refuses rather than let
you discover that the hard way.

## Credits

- [OpenIPC](https://github.com/OpenIPC) — firmware and buildroot
- [divinus](https://github.com/OpenIPC/divinus) — the streamer
- [`mtrakal/ipc-vatilon`](https://github.com/mtrakal/ipc-vatilon) — community
  documentation of this OEM family
- `OpenIPC/firmware#1610` — the open issue tracking this camera family

## Warning

Flashing can brick a camera. You are replacing the bootable firmware of a device
whose vendor provides no recovery path. Back up first, and for your first
conversion keep serial access available if you can.
