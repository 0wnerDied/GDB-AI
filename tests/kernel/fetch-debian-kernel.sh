#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OUTPUT_DIRECTORY 6.1|6.12|6.12-arm64" >&2
    exit 2
fi

mkdir -p "$1"
# 2026-08-29: Cargo starts integration binaries from the crate directory;
# emit absolute artifact paths so a relative output directory remains valid.
output=$(CDPATH= cd -- "$1" && pwd)
architecture=x86_64
busybox_url=
busybox_sha=
module_name=irqbypass
# 2026-10-08: Debian pruned 6.12.105 packages; keep each refreshed image,
# debug file, and module pinned to the same distribution build.
# ponytail: live pools prune old builds; refresh these pins when retired.
case $2 in
    6.1)
        release=6.1.0-50-cloud-amd64
        image_url=https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/linux-image-6.1.0-50-cloud-amd64_6.1.176-1_amd64.deb
        image_sha=efe19f605b6f54a8352e68d85a629abb2d30b72a085faef603a9152590baa791
        debug_url=https://deb.debian.org/debian/pool/main/l/linux/linux-image-6.1.0-50-cloud-amd64-dbg_6.1.176-1_amd64.deb
        debug_sha=4657321b206b13f95d21d23c4644636f14b2acfaeed9375a4b5e200fe1a9c0d9
        module_layout=core_layout
        module_relative=lib/modules/$release/kernel/virt/lib/irqbypass.ko
        module_compression=none
        ;;
    6.12)
        release=6.12.111+deb13-amd64
        image_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux/linux-image-6.12.111+deb13-amd64-unsigned_6.12.111-1_amd64.deb
        image_sha=0dd8541215c133f7df9e80a49c0b6e89e8680c4de364fc41bfb3a9ca81a6e4e4
        debug_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux/linux-image-6.12.111+deb13-amd64-dbg_6.12.111-1_amd64.deb
        debug_sha=3270929e0dae6fea0da5ecaf4bd250a43171352507724879bc3d134266f9f2a5
        module_layout=module_memory
        module_relative=usr/lib/modules/$release/kernel/virt/lib/irqbypass.ko.xz
        module_compression=xz
        ;;
    6.12-arm64)
        architecture=aarch64
        release=6.12.111+deb13-cloud-arm64
        image_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux-signed-arm64/linux-image-6.12.111+deb13-cloud-arm64_6.12.111-1_arm64.deb
        image_sha=d7c5c91a5fe4bbe59b63b9455044fdb6727b0833d1d878918fc0893388b2c781
        debug_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux/linux-image-6.12.111+deb13-cloud-arm64-dbg_6.12.111-1_arm64.deb
        debug_sha=eea03037048ff9bd6d6d13872435a38d465048c59c2f232c39e10b4fb4fc69cf
        # 2026-09-21: Debian pruned the b8 rebuild; pin its available b9
        # replacement and checksum so arm64 kernel CI remains reproducible.
        busybox_url=https://deb.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-6+b9_arm64.deb
        busybox_sha=c833be48abfa16bc19c4966ec93e289ff1ce5d2f1476cad3a57bd105378cd15c
        module_layout=module_memory
        module_name=brd
        module_relative=usr/lib/modules/$release/kernel/drivers/block/brd.ko.xz
        module_compression=xz
        ;;
    *)
        echo "unsupported Debian kernel series: $2" >&2
        exit 2
        ;;
esac

downloads=$output/downloads
root=$output/$release
mkdir -p "$downloads" "$root"

fetch() {
    url=$1
    sha=$2
    file=$downloads/${url##*/}
    if [ ! -f "$file" ]; then
        echo "downloading ${url##*/}" >&2
        curl --fail --location --retry 3 --output "$file.part" "$url"
        printf '%s  %s\n' "$sha" "$file.part" | sha256sum --check --status
        mv "$file.part" "$file"
    fi
    printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status
    printf '%s\n' "$file"
}

image_deb=$(fetch "$image_url" "$image_sha")
debug_deb=$(fetch "$debug_url" "$debug_sha")
busybox=
if [ -n "$busybox_url" ]; then
    busybox_deb=$(fetch "$busybox_url" "$busybox_sha")
    busybox_relative=usr/bin/busybox
    busybox=$root/$busybox_relative
    if [ ! -f "$busybox" ]; then
        dpkg-deb --fsys-tarfile "$busybox_deb" |
            tar -x -C "$root" "./$busybox_relative"
    fi
fi
image_relative=boot/vmlinuz-$release
vmlinux_relative=usr/lib/debug/boot/vmlinux-$release
image=$root/$image_relative
vmlinux=$root/$vmlinux_relative
module_source=$root/$module_relative
module=$module_source

if [ ! -f "$image" ] || [ ! -f "$vmlinux" ] || [ ! -f "$module_source" ]; then
    dpkg-deb --fsys-tarfile "$image_deb" |
        tar -x -C "$root" "./$image_relative" "./$module_relative"
    dpkg-deb --fsys-tarfile "$debug_deb" |
        tar -x -C "$root" "./$vmlinux_relative"
fi

if [ "$module_compression" = xz ]; then
    module=$root/$module_name.ko
    if [ ! -f "$module" ]; then
        xz --decompress --stdout "$module_source" > "$module"
    fi
fi

for file in "$image" "$vmlinux" "$module"; do
    if [ ! -f "$file" ]; then
        echo "Debian kernel artifact is missing: $file" >&2
        exit 1
    fi
done
if [ -n "$busybox" ] && [ ! -f "$busybox" ]; then
    echo "Debian busybox artifact is missing: $busybox" >&2
    exit 1
fi

printf 'GDB_AI_KERNEL_IMAGE=%s\n' "$image"
printf 'GDB_AI_KERNEL_VMLINUX=%s\n' "$vmlinux"
printf 'GDB_AI_KERNEL_MODULE=%s\n' "$module"
printf 'GDB_AI_KERNEL_RELEASE=%s\n' "$release"
printf 'GDB_AI_KERNEL_MODULE_LAYOUT=%s\n' "$module_layout"
printf 'GDB_AI_KERNEL_ARCH=%s\n' "$architecture"
printf 'GDB_AI_KERNEL_MODULE_NAME=%s\n' "$module_name"
if [ -n "$busybox" ]; then
    printf 'GDB_AI_KERNEL_BUSYBOX=%s\n' "$busybox"
fi
