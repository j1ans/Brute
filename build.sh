#!/bin/sh
# Cross-compile brute for a 64-bit A7 (iPhone 5S) ramdisk environment.
#   ./build.sh               -> ./brute        (min iOS 8.0, tested on 8.3)
#   ./build.sh 7.0           -> ./brute        (min iOS 7.0, tested on 7.1.2)
#
# Requires Xcode + iPhoneOS SDK (IOKit headers are included in the SDK).
# No codesigning needed: the ramdisk kernel boots with
#   amfi=0xff cs_enforcement_disable=1
#
# The bsdcrypto sources are pulled from a local clone of
# https://github.com/dinosec/iphone-dataprotection (ramdisk_tools/bsdcrypto).
# Set IPDP to that checkout if it is not at ../iphone-dataprotection.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IPDP=${IPDP:-$HERE/../iphone-dataprotection}
SRC="$IPDP/ramdisk_tools"
MINIOS=${1:-8.0}
SDK=$(xcrun --sdk iphoneos --show-sdk-path)

xcrun --sdk iphoneos clang \
  -target arm64-apple-ios${MINIOS} \
  -Os -Wall \
  -isysroot "$SDK" \
  -I "$SRC" \
  "$HERE/brute.c" \
  "$SRC/bsdcrypto/pbkdf2.c" \
  "$SRC/bsdcrypto/sha1.c" \
  "$SRC/bsdcrypto/rijndael.c" \
  "$SRC/bsdcrypto/key_wrap.c" \
  -framework CoreFoundation -framework IOKit \
  -o "$HERE/brute"

file "$HERE/brute"
echo "OK: $HERE/brute (min iOS ${MINIOS})"
