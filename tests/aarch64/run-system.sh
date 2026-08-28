#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
fi

repository=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
output=$1
work=$(mktemp -d "${TMPDIR:-/tmp}/gdb-ai-aarch64-system.XXXXXX")
container=gdb-ai-aarch64-system-$$
image=debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    find "$work" -depth -delete
}
# 2026-08-29: A signal handler that only cleans up can return into the build
# with a deleted workspace; exit first and let the EXIT trap clean up once.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in aarch64-linux-gnu-gcc aarch64-linux-gnu-strip cargo docker \
    mkfs.ext4 qemu-system-aarch64 rustup tar timeout; do
    command -v "$command" >/dev/null || {
        echo "missing AArch64 system-test command: $command" >&2
        exit 1
    }
done

mkdir -p "$output" "$work/rootfs" "$work/tests"
rustup target add aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_DIR="$work/cargo-target" \
    cargo test --locked -p gdb-ai-core \
        --target aarch64-unknown-linux-gnu \
        --test vertical --test core --test remote --no-run

copy_test() {
    name=$1
    source=
    for candidate in \
        "$work/cargo-target/aarch64-unknown-linux-gnu/debug/deps/$name-"*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            [ -z "$source" ] || {
                echo "multiple AArch64 $name test executables found" >&2
                exit 1
            }
            source=$candidate
        fi
    done
    [ -n "$source" ] || {
        echo "AArch64 $name test executable was not built" >&2
        exit 1
    }
    install -m 755 "$source" "$work/tests/$name"
    aarch64-linux-gnu-strip --strip-debug "$work/tests/$name"
}

copy_test vertical
copy_test core
copy_test remote

docker run --name "$container" --platform linux/arm64 "$image" sh -ec '
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        busybox-static gdb gdbserver gcc libc6-dev linux-image-cloud-arm64
    apt-get clean
    rm -rf /var/lib/apt/lists/*
'
docker export "$container" | tar --no-same-owner -x -C "$work/rootfs"

guest_repository="$work/rootfs$repository"
mkdir -p "$guest_repository/crates/gdb-ai-core" \
    "$guest_repository/tests/targets" \
    "$guest_repository/target/aarch64-system-tests"
cp -a "$repository/tests/targets/c" "$guest_repository/tests/targets/"
for test_name in vertical core remote; do
    install -m 755 "$work/tests/$test_name" \
        "$guest_repository/target/aarch64-system-tests/$test_name"
done
install -m 755 "$repository/tests/aarch64/guest-init" "$work/rootfs/init"
cp -L "$work/rootfs"/boot/vmlinuz-* "$work/kernel"
cp -L "$work/rootfs"/boot/initrd.img-* "$work/initrd"

truncate -s 2G "$work/rootfs.img"
mkfs.ext4 -q -F -d "$work/rootfs" "$work/rootfs.img"

timeout 15m qemu-system-aarch64 \
    -machine virt,accel=tcg -cpu max -m 2048 -smp 2 \
    -kernel "$work/kernel" -initrd "$work/initrd" \
    -append "root=/dev/vda rw console=ttyAMA0 quiet init=/init panic=-1 gdb_ai_repo=$repository" \
    -drive "file=$work/rootfs.img,format=raw,if=virtio,cache=unsafe" \
    -nographic -no-reboot > "$output/serial.log" 2>&1

cat "$output/serial.log"
grep -q '^GDB_AI_AARCH64_VM_RESULT=0' "$output/serial.log"
