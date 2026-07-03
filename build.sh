#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Optional opt-in: --firmware runs the EXPERIMENTAL multi-partition firmware OC
# (mcupm/sspm/pi_img) after the bootloader inject. Strip it before positional args.
DO_FIRMWARE=0
POSARGS=()
for arg in "$@"; do
    case "$arg" in
        --firmware) DO_FIRMWARE=1 ;;
        *) POSARGS+=("$arg") ;;
    esac
done
set -- "${POSARGS[@]}"

DEVICE="${1:-pacman}"
DEVICE_LOWER=$(echo "$DEVICE" | tr '[:upper:]' '[:lower:]')

if [ -n "$2" ]; then
    BOOTLOADER="$2"
else
    BOOTLOADER="bin/${DEVICE_LOWER}.bin"
fi

HOST_ARCH="$(uname -m)"

case "$HOST_ARCH" in
    x86_64)
        TOOLCHAIN_HOST="x86_64"
        ;;
    aarch64|arm64)
        TOOLCHAIN_HOST="aarch64"
        ;;
    *)
        echo -e "${RED}Unsupported host architecture: $HOST_ARCH${NC}"
        exit 1
        ;;
esac

TOOLCHAIN_VERSION="14.2.rel1"

TOOLCHAIN_URL="https://developer.arm.com/-/media/Files/downloads/gnu/${TOOLCHAIN_VERSION}/binrel/arm-gnu-toolchain-${TOOLCHAIN_VERSION}-${TOOLCHAIN_HOST}-aarch64-none-elf.tar.xz"
TOOLCHAIN_ARCHIVE="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-${TOOLCHAIN_HOST}-aarch64-none-elf.tar.xz"
TOOLCHAIN_DIR="arm-gnu-toolchain-${TOOLCHAIN_VERSION}-${TOOLCHAIN_HOST}-aarch64-none-elf"
TOOLCHAIN_PATH="$(pwd)/$TOOLCHAIN_DIR/bin"

if [ ! -d "$TOOLCHAIN_PATH" ]; then
   echo -e "${YELLOW}Downloading toolchain...${NC}"
   
   if command -v wget &> /dev/null; then
       wget -O "$TOOLCHAIN_ARCHIVE" "$TOOLCHAIN_URL"
   elif command -v curl &> /dev/null; then
       curl -L -o "$TOOLCHAIN_ARCHIVE" "$TOOLCHAIN_URL"
   else
       echo -e "${RED}Error: Need wget or curl to download toolchain${NC}"
       exit 1
   fi
   
   echo -e "${YELLOW}Extracting toolchain...${NC}"
   tar -xf "$TOOLCHAIN_ARCHIVE"
   rm -f "$TOOLCHAIN_ARCHIVE"
fi

export PATH="$TOOLCHAIN_PATH:$PATH"

if [ ! -f "$BOOTLOADER" ]; then
   echo -e "${RED}Error: Bootloader file '$BOOTLOADER' not found${NC}"
   exit 1
fi

echo
echo -e "${BOLD}Building for device: ${BLUE}$DEVICE${NC}"
echo -e "${BOLD}Bootloader: ${BLUE}$BOOTLOADER${NC}"
echo

rm -f *.patched
rm -rf payload/build

echo -e "${YELLOW}Building payload...${NC}"
(cd payload && make clean && make DEVICE="$DEVICE" all -j$(nproc))

if [ $? -ne 0 ]; then
   echo -e "${YELLOW}Warning: Payload build failed or skipped. Continuing with patches only...${NC}"
fi

if [ $? -ne 0 ]; then
   echo -e "${RED}Build failed${NC}"
   exit 1
fi

echo
echo -e "${YELLOW}Injecting payload...${NC}"
./inject.sh "$DEVICE" "$BOOTLOADER"

echo

FW_PY="./.venv/bin/python3"
[ -x "$FW_PY" ] || FW_PY="python3"
SIGNED_BOOTLOADER="${DEVICE_LOWER}-fenrir-signed.bin"
if [ -f "${DEVICE_LOWER}-fenrir.bin" ]; then
   echo -e "${YELLOW}Re-signing patched bootloader...${NC}"
   "$FW_PY" -c "import sys; sys.path.insert(0, 'injector'); import fw_sign; fw_sign.sign_image(sys.argv[1], sys.argv[2])" "${DEVICE_LOWER}-fenrir.bin" "$SIGNED_BOOTLOADER" || {
       echo -e "${RED}Bootloader re-sign failed${NC}"; exit 1; }
   echo -e "${GREEN}Operation completed successfully!${NC}"
   echo -e "${WHITE}Patched bootloader saved as: ${BOLD}${DEVICE_LOWER}-fenrir.bin${NC}"
   echo -e "${WHITE}Signed bootloader saved as: ${BOLD}${SIGNED_BOOTLOADER}${NC}"
else
    echo -e "${RED}Injection failed or output file not found!${NC}"
    exit 1
fi

if [ "$DO_FIRMWARE" -eq 1 ]; then
    echo
    echo -e "${YELLOW}Running EXPERIMENTAL firmware-partition OC (--firmware)...${NC}"
    echo -e "${YELLOW}  UNVERIFIED per silicon — flash & verify on-device.${NC}"
    "$FW_PY" injector/patch_firmware.py "$DEVICE" || {
        echo -e "${RED}Firmware OC step failed${NC}"; exit 1; }
fi