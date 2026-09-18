# Brute

On-device passcode brute-force for **64-bit A7 devices (iPhone 5S, iPhone6,1/6,2)** running **iOS 7.1.x / 8.x**, executed inside a pwned-iBoot (checkm8) SSH ramdisk where the data partition `/mnt2` is mounted read-write with the `protect` flag.

Adapted to arm64 / iOS 7-8 / A7 from the classic
[iPhone-protection](https://github.com/dinosec/iphone-dataprotection) (`ramdisk_tools`) — see **Credits**.

Verified on real hardware:

- iPhone 5S (A7, S5L8960X), **iOS 8.3 (12F70)** — dictionary hit confirmed (passcode found at entry #5)
- iPhone 5S (A7), **iOS 7.1.2 (11D257)** — runs unmodified, just recompile with `-target arm64-apple-ios7.0`

## Build

```sh
git clone https://github.com/dinosec/iphone-dataprotection   # for the bsdcrypto sources
git clone https://github.com/j1ans/Brute
cd Brute
./build.sh          # min iOS 8.0
./build.sh 7.0      # min iOS 7.x
```

Then copy `brute` to the device (e.g. to the writable data partition) and run it over SSH:

```sh
scp -O -P <port> brute root@localhost:/mnt2/tmp/
ssh -p <port> root@localhost
chmod +x /mnt2/tmp/brute
/mnt2/tmp/brute -k -r 5 /mnt2/tmp/dict_0000_9999.txt
```

## Usage

```
brute [-k] [-r N] <dictionary_file> [keybag_path]
brute -K <passcode> [keybag_path]    # single candidate test
brute -D                             # dump effaceable storage / device keys
```

| Mode | Meaning |
|---|---|
| default | userland passcode-key recompute (the pre-A7 "no-SEP" path) — see note below |
| `-k` | kernel **AppleKeyStore** path — this is the one that works on A7 |
| `-r N` | rebuild the keybag handle + user-client connection every N consecutive failures (SEP throttle dodge) |
| `-K` | try one passcode, print the kernel verdict |
| `-D` | dump effaceable bytes, key835/key89B (diagnostics) |

Dictionary format: one candidate per line (e.g. `dict/dict_0000_9999.txt`).
Default keybag path: `/mnt2/keybags/systembag.kb`.

A hit prints `*** FOUND ***` and exits 0.

## How the iOS 7/8 64-bit (A7) port was fixed

The original `ramdisk_tools` targets 32-bit ARM (armv6/armv7, iOS 4-6). Making it work on arm64 A7 required the following, each verified on-device:

### 1. arm64 `IOAESAccelerator` request layout

The kernel-side request struct is a **fixed 88-byte layout** on arm64
(`cleartext@0, ciphertext@8, size@16, iv@20, mode@36, bits@40, key@44, mask@76, uidplus_len@80`).
The old 32-bit size fallbacks (`76/80`) always return `kIOReturnBadArgument`.
`brute` probes the accepted size once and caches it.

**Separate in/out structs matter**: the kernel writes a response struct back that does *not* echo `mask`/`key`, so reusing one buffer as both request and response silently zeroes the mask from the second call on (observed as `mask=0x0` failures). `AppleKeyStore_derivation()` in the original code used distinct `in`/`out` globals for exactly this reason.

### 2. The BAG1 locker is plaintext on A7

On older devices the effaceable lockers are stored encrypted. On A7 (iOS 7.1/8.3 tested), `AppleEffaceableStorage` user client selector 5 (`getLocker`) returns the **plaintext** 52-byte payload:

```
'1GAB' (magic, stored byte-reversed) || IV[16]  (== _MKBIV from systembag.kb) || key[32]
```

`_MKBPAYLOAD` then decrypts with plain **AES-256-CBC (PKCS7)** using that key/iv, yielding the inner plist with `KeyBagKeys` (the `DATA`/`SIGN` blob). The tool validates every candidate key/iv pair against the `bplist00` magic of the decrypted payload before using it — no magic-guessing.

### 3. Pure userland verification is impossible on A7 — call the kernel instead

The pre-A7 flow recomputes the passcode key entirely in userland:
`PBKDF2(passcode, salt, 1 iter) -> UID-AES "tangle" (iter x 4KB CBC) -> RFC3394 unwrap of passcode-wrapped class keys`.

On A7 that chain computes a *wrong* key: the keybag's device/passcode wrapping keys live in the **SEP key hierarchy**, not the AP one. Proof (milestone M1): `key835` (UID-AES of the `01*16` seed, correctly derived — `key89B` matches the kernel's cached derived-key table) **cannot unwrap the keybag's HMCK**, and the kernel's derived-key table contains no 0x835 entry at all.

The fix is to verify passcodes **exactly like a non-SEP device does at the API level** — through the `AppleKeyStore` user client, whose selector numbering is unchanged:

```
0  init
6  AppleKeyStoreKeyBagCreateWithData(decrypted KeyBagKeys blob)  -> keybag handle
5  AppleKeyStoreKeyBagSetSystem(handle)
9  AppleKeyStoreUnlockDevice(passcode bytes)   -> 0 == correct passcode
```

With the SEP alive (loaded via the stock `seputil --load` flow), the SEP executes underneath and the verdict is authoritative. `brute -k` is this path.

### 4. SEP throttle and the `-r N` dodge

After ~5-6 consecutive failed `UnlockDevice` calls the SEP imposes a **~5 s delay per attempt** (128 ms → 5134 ms observed). Two properties defeat it:

- a **successful unlock resets** the consecutive-failure counter, and
- the counter is bound to the keybag handle / user-client connection.

`-r 5` therefore rebuilds the handle + connection every 5 failures (selector 4 release, close, re-create). Measured effect: attempts stay at **~128-136 ms** forever (20-in-a-row test: all fast, 4 silent rebuilds, ~185 ms amortized).

### 5. Performance

| | observed |
|---|---|
| per attempt | 128 ms (iOS 8.3) / 136 ms (iOS 7.1.2) |
| amortized with `-r 5` | ~185-195 ms |
| full 0000-9999 | **~31 minutes** (throttled: ~14 h) |

## Requirements

- iPhone 5S in a checkm8 pwned ramdisk (e.g. an ios8-sshrd / SSHRD_Script-style environment) with `/dev/disk0s1s2` mounted on `/mnt2` (rw, `protect`)
- kext mode needs only the `AppleKeyStore` service and a readable keybag — the plaintext BAG1 locker means **no UID-AES kernel patch is required** for `-k` (device keys are still derived and printed when the patch is present; userland mode needs it)
- iOS 7.1.2 needed no code changes beyond the deployment target

## Credits

- **iPhone-protection** — [dinosec/iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection) (Sogeti R&D / Jean-Baptiste Beliard, Jean Sigwald, Raul Siles): the passcode KDF, keybag parsing, key-wrap and IOKit glue this tool is derived from (`ramdisk_tools`, `bsdcrypto`)
- The checkm8 ramdisk ecosystem: checkm8/ipwnder, Legacy-iOS-Kit, SSHRD_Script and the ios8-sshrd toolchain that restores `/mnt2` mounting with SEP alive on A7

## Disclaimer

For research on **your own devices** only. The device passcode in all tests above was set by the researcher.
