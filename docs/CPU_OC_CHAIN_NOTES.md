# MT6789 (fenrir) CPU overclock chain — full map

Personal fork notes. OC reference material credited to [@raffprjkt](https://t.me/raffprjkt).

End-to-end trace of where CPU frequency is controlled on this device, so the OC
knobs (and non-knobs) are unambiguous. Companion to `PI_IMG_KRAKEN_NOTES.md`
(the aging/EEMSN ceiling) and the two patchers `mcupm_devices.py` /
`pi_img_devices.py`.

SoC: MediaTek MT6789 (Helio G99) — 2× Cortex-A76 (BIG) + 6× Cortex-A55 (LITTLE).
Device slot: `_a`. All device access below is **pull/read-only — never flash**.

---

## 0. TL;DR — the chain, and what is editable

```
 mcupm.img (RISC-V RV33 firmware)                 <-- EDITABLE: mcupm_devices.py
   OPP anchor tables (max/throttle/low + EEMSN freq/volt)
        │  populates
        ▼
 CPU-DVFS SRAM LUT  (CSRAM 0x11bc00, perf-domain0 0x11bc10, domain1 0x11bd30)
        │  read by
        ▼
 mtk-cpufreq-hw driver (vendor .ko in vendor_boot, NOT vmlinux)  <-- no static table
   generates the full 16/24-step ladder from SRAM anchors + PLL/clk-div/regulators
   (reads SRAM via ioremap; holds no freq constants — not a firmware-patch target)
        │  exposes
        ▼
 /sys/.../cpufreq/policy0 (LITTLE)  policy6 (BIG)   scaling_driver = mtk-cpufreq-hw

 GATE (separate): EEMSN module in mcupm validates volt/freq vs pi_img aging data
   → "[CPU][EEMSN]...vboot violate" refuses OC past a per-chip threshold
   pi_img.bin  <-- EDITABLE w/ re-sign: pi_img_devices.py  (see KRAKEN notes)
```

**Only two things are editable to move CPU freq: `mcupm.img` (the anchors) and,
for the hard ceiling, `pi_img.bin` (aging envelope). The kernel side holds no
static CPU OPP table.**

---

## 1. Kernel side is a DEAD END for the freq ladder (proven 3 ways)

1. `scaling_driver = mtk-cpufreq-hw` on both `policy0` and `policy6`.
2. DTB (`lk_main_dtb.bin`, v17): CPU nodes `cpu@000..005` (A55) / `cpu@100..101`
   (A76) are **bare — no `operating-points`/`opp-hz`**. The only `opp-table-*`
   nodes are peripheral (disp/mdp/venc/vdec/cam/img/ipe) and `/soc/opp-table0`
   (bus/CCI ~1.1GHz..390MHz). None are CPU cores.
3. Neither MTK cpufreq module holds a static table — both read the ladder from SRAM:
   - `cpudvfs.ko` (`/vendor_dlkm/lib/modules/`, 30 096 B): zero CPU-freq constants;
     pure proc/eem glue — `cpufreq_debug_proc_*` (the `/proc/cpudvfs` node),
     `eem_cur_volt_proc_*`, `get_devinfo`, `mtk_eem_init`; imports
     `cpufreq_cpu_get` / `dev_pm_opp_find_freq_floor` (consumes the ladder, never
     defines it).
   - `mediatek-cpufreq-hw.ko` (the `scaling_driver`, 28 296 B): zero freq constants;
     builds the table at runtime (`mtk_cpu_create_freq_table`,
     `mtk_cpufreq_hw_target_index`) by ioremapping the perf-domain SRAM
     (`devm_platform_ioremap_resource`; of_match `"mediatek,cpufreq-hw"`).

   Both are **vendor modules in the vendor_boot ramdisk** (`lib/modules/`), loaded
   early and live in `/proc/modules`. The GKI `vmlinux` (5.10.x-android12) carries
   only the generic cpufreq **core** (`cpufreq_register_driver` + exported OPP
   symbols) — no MTK driver, no `mediatek,cpufreq-hw` string. Swapping the GKI
   kernel therefore leaves cpufreq intact: the vendor module loads from vendor_boot
   and reads the ladder from SRAM regardless of the vmlinux in use.

### DTB DVFS bindings (for reference)
```
mediatek,cpufreq-hybrid:
  reg = USRAM 0x114400/0xc00, CSRAM 0x11bc00/0x1400, ESRAM 0x112800/0x1800,
        mcucfg 0x114f40/0xc0
  tbl-off      = <0x04 0x4c 0x94>
  cslog-range  = <0x3d0 0xfa0>
  pll-con      = <0x20c 0x21c 0x25c>
  clk-div      = <0xa2a0 0xa2a4 0xa2e0>
  proc1/2/3-supply, sram-supply   (regulators = voltage ceiling)
  nvmem-cells  = "lkginfo"        (segment/binning)
mediatek,cpufreq-hw:
  reg = performance-domain0 0x11bc10/0x120, performance-domain1 0x11bd30/0x120
```
The ladder LUT lives in this SRAM at runtime, populated by firmware — not stored in
any partition as an explicit table. `/dev/mem` is absent on-device (no direct SRAM
dump), but the **effective ladder is readable live** via the Energy Model:
`/sys/kernel/debug/energy_model/cpu{0,6}/ps:*/{frequency,power,cost}` — 24 LITTLE
OPPs (500→2000 MHz) + 16 BIG OPPs (725→2200 MHz), matching
`scaling_available_frequencies`. The min OPP (500 / 725) is simply the lowest EM
step — there is no separate "min floor" record in play (§6).

---

## 2. Ground-truth validation: device `mcupm_a` == `mcupm_devices.py --big 2600`

Pulled the live `mcupm_a` partition and diffed against stock `mcupm.img`. The
device runs an OC to BIG 2600, and the diff is **exactly** what
`mcupm_devices.py --big 2600 --little` emits — confirming both that
`mcupm_devices.py` is correct and that mcupm anchors are the CPU freq source.

| file off | stock → device | meaning / script formula |
|---|---|---|
| 0x1488c | 5f → 64 | thermal high 95 → 100 °C |
| 0x14890 | 55 → 64 | thermal low 85 → 100 °C |
| 0x15fec | 2000 → 2364 | compact throttle row (`2000·2600/2200`) |
| 0x15ff2 | 650 → 768 | LITTLE col (`650·2364/2000`) |
| 0x16000 | 2200 → 2600 | compact max row (BIG) |
| 0x16004 | 725 → 857 | LITTLE col (`725·2600/2200`) |
| 0x16014 | 1540 → 1820 | compact low row (`1540·2600/2200`) |
| 0x16598 | 2000 → 2364 | governor BIG throttle |
| 0x165b0 | 1600 → 1891 | governor BIG low throttle |
| 0x16670 | 2200 → 2600 | governor BIG max |
| 0x16688 | 1650 → 1950 | governor BIG low max |
| 0x17b88 | 2000 → 2200 | DVFS timer (`--little`) |
| 0x17cb4 | 2200 → 2600, volt 1024 → 1085 | EEMSN freq + `_auto_volt(2600)` |
| 0x17d80 | 1540 → 1950-ish | DVFS timer low |

30 bytes across 14 runs — all inside the tables already mapped in
`mcupm_devices.py`. Nothing else in the partition changed.

---

## 3. Other DVFS-family partitions — checked, not the ladder

Pulled read-only from slot `_a`:

| partition | fwid | verdict |
|---|---|---|
| `mcupm_a` | tinysys-mcupm-RV33_A | CPU DVFS anchors — THE knob (see §2) |
| `pi_img_a` | (GFH `pi_img`) | aging/EEMSN envelope; **md5 == loose `pi_img.bin`** |
| `sspm_a` | tinysys-sspm (720 KB) | thermal/power/QoS budget only — holds a LITTLE `500000` record table (×8) **and** a `(cpu_freq × dram_freq)` DVFS-bandwidth map (the `725000` "BIG floor" is a key in *that* map, not a floor record — see §6); no CPU ladder |
| `spmfw_a` | spmfw (14 KB) | SPM sleep firmware — no CPU freq |

Conclusion: no firmware partition stores an explicit full CPU ladder. It is
generated by the `cpufreq-hybrid` driver from mcupm anchors + PLL/clk-div.

### Partition map (by-name, slot _a)
```
mcupm_a  sdc25   pi_img_a sdc21   sspm_a  sdc24   spmfw_a sdc20
scp_a    sdc23   lk_a     sdc27   dtbo_a  sdc31   boot_a  sdc28
md1img_a sdc19   tee_a    sdc32   seccfg  sdc17   proinfo sdc34
```
All firmware partitions are 1 MB slots (GFH image at start, 0xFF/0x00 padded).

---

## 4. What moves CPU freq, and the ceiling

- **Raise freq up to the EEMSN threshold:** `mcupm_devices.py --big <MHz>`
  (validated to 2600 on-device). This is the whole job below the wall.
- **Min freq (LITTLE 500 / BIG 725):** kernel/DTS + hardware-owned (`mtk-cpufreq-hw`
  perf-domain SRAM LUT), NOT in mcupm/sspm as an editable clamp — on-device verified
  (§6a-bis). See `mcupm_devices.py` docstring "MIN FREQ" note.
- **Hard ceiling past a threshold:** EEMSN (`vboot violate`) validating against
  `pi_img.bin` aging data. This is firmware, not kernel. Editing path:
  `pi_img_devices.py` (patch payload[4:-4] + cert_bypass re-sign). The exact
  byte that encodes the cap is not yet pinned — `PI_IMG_KRAKEN_NOTES.md` §6c/§7.

## 5. Next step (not done yet)
Finish the EEMSN validator trace in mcupm (RISC-V) to name which shadowed EEM
byte = the OC ceiling, per `PI_IMG_KRAKEN_NOTES.md` §7 (r2 with forced function
boundaries at the EEMSN log-call sites, or ESIL emulation of fn ~0x3a1e callers).
Only then can `pi_img_devices.py` gain a verified cap patch.

---

## 6. The `500000`/`725000` records are DVFS/QoS data, not a min-freq clamp

`scaling_min_freq` (LITTLE 500 / BIG 725 MHz) is owned by `mtk-cpufreq-hw` + the
perf-domain SRAM LUT (§1, §4): the minimum is just the lowest OPP the driver builds
from SRAM. The `500000`/`725000` values that also appear in `mcupm.img`/`sspm.img`
are power/thermal-envelope and DRAM-bandwidth data — rewriting them does not move
the cpufreq minimum. What each record is:

### 6a. What the records are
The 40-byte record shape `[freq_kHz u32][0x0013bdb6][…]` (`0x0013bdb6` = 1293750, a
constant power/budget coefficient) holds `500000` (`0x0007a120`) in:

| image | `500000` records |
|---|---|
| `mcupm.img` | **×4** — the `[C]` power/thermal-envelope table @ file 0x147f0 (stride 0x28) |
| `sspm.img`  | **×8** — @ file 0x18f0 (stride 0x24) |

The `725000` values in `sspm` are not floor records. Their 7 occurrences
(0x179c…0x1824) carry **no** `0x0013bdb6` marker, sit at irregular stride, and are
each paired with a descending DRAM data rate:

```
0x179c: 725000, 4266000    0x17cc: 725000, 1866000    (DRAM data rates:
0x17a4: 725000, 3200000    0x17e4: 725000, 1600000     4266/3200/2400/
0x17b4: 725000, 2400000    0x1804: 725000, 1200000     1866/1600/1200/
                           0x1824: 725000,  800000     800 MHz)
```

…interleaved with `650000/600000/550000` CPU rows: a `(cpu_freq × dram_freq)`
DVFS→DRAM-bandwidth / QoS map, where `725000` is a lookup key (`725000` =
`0x000b1008`).

### 6b. How the minimum is actually enforced
- **On-device (INOI A75, mt6789, `adb` root):** `policy0` (LITTLE, cpu0-5) and
  `policy6` (BIG, cpu6-7) both use `scaling_driver = mtk-cpufreq-hw`;
  `cpuinfo_min_freq` = 500000 / 725000. Writing `scaling_min_freq = 200000` clamps
  straight back to `500000` — the floor is enforced by the driver/HW.
- **Device tree (live `/proc/device-tree`):** CPU nodes carry `performance-domains`
  but no `operating-points`/`opp-hz`; the ladder + min OPP come from the
  `mtk-cpufreq-hw` perf-domain SRAM LUT (§1).
- **mcupm (RISC-V):** the `[C]` table @0x147f0 has zero code references (the RISC-V
  analyzer resolves 236 other data refs, including the §2 OC-anchor tables). It is
  passive data mcupm's DVFS path never reads.

The `725000`×7 set is the DRAM-bandwidth map above, so rewriting it corrupts that
map rather than setting any floor.

### 6c. Signing / cert requirements per partition
`mcupm.img` and `pi_img.bin` are GFH-wrapped and RSA cert2-signed, and load +
re-sign cleanly through `liblk` + fenrir's local `cert_bypass`:

| image | fwid | cert1/cert2 | note |
|---|---|---|---|
| `mcupm.img` | tinysys-mcupm-RV33_A | @0x1eab8/0x1f378 | device runs a **raw byte-patched** mcupm (no cert change) and boots → this **unlocked** unit does NOT enforce mcupm cert2 |
| `pi_img.bin`| pi_img | (KRAKEN, §KRAKEN notes) | already re-signed by `pi_img_devices.py` |

`mcupm_devices.py` writes **raw** by default; `--sign` adds a re-sign step (shared
`fw_sign.py`). On-device acceptance of the forged cert2 is **UNTESTED** (KRAKEN §6d).

### 6d. Build wiring (all under `injector/`)

| file | role |
|---|---|
| `injector/fw_sign.py` | shared `liblk`+local `cert_bypass` re-sign (`sign_image`, OVERRIDE default, WRAP fallback) |
| `injector/mcupm_devices.py` | CPU freq: `--big` / `--floor` / `--little` / `--volt` / `--thermal` + `--sign` |
| `injector/pi_img_devices.py` | `--set`/`--set-reg` + `--write` (always re-signs) |
| `injector/patch_gpufreq.py` | GPU OPP table in `mtk_gpufreq_mt6789.ko`: `--bp` / `--oc` / `--volt` |
| `injector/devices.py` | per-device `firmware={'mcupm':{…},'pi_img':{…},'gpufreq':{…}}` |
| `injector/patch_firmware.py` | orchestrator: reads the device's `firmware` block, runs each patcher with ITS own flags, emits `<device>-<part>` images |
| `build.sh` | `--firmware` opt-in flag → runs `patch_firmware.py <device>` after inject |

**Usage**
```bash
# 1. put the device's stock images in bin/firmware/<device>/: mcupm.img pi_img.bin
# 2. edit the device's firmware={…} block in injector/devices.py, e.g.:
#      'mcupm':  {'big': 2600, 'little': True, 'sign': True},
#      'pi_img': {'set_reg': ['0x11c10580=0x2000'], 'sign': True},
# 3. build with the opt-in flag (must use the liblk venv for signing):
./build.sh A75 --firmware
#    → a75-fenrir.bin (bootloader) + a75-mcupm.img + a75-pi_img.bin
```

**Guarantees / caveats**
- Every knob defaults to stock/no-op; a partition with no actionable flag or a
  missing input image is **skipped**. Default `./build.sh <dev>` (no `--firmware`)
  is unchanged (bootloader-only).
- All outputs are **file-only — nothing is flashed.** Flashing is the user's step.
- `mcupm --big` is the CPU-freq path validated on real hardware (§2). The forged
  cert2 re-sign path is still untested on-device — verify any signed partition
  boots before trusting it.
