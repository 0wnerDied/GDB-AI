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
        release=6.12.105+deb13-amd64
        image_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux/linux-image-6.12.105+deb13-amd64-unsigned_6.12.105-1_amd64.deb
        image_sha=31eb52a588ba7f34294f0ca31ea48f007351e40373e6a022ac9bf8fc7c131e3f
        debug_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux/linux-image-6.12.105+deb13-amd64-dbg_6.12.105-1_amd64.deb
        debug_sha=34b4c2abfa74eecbbe1e6b696e4ddf6854d3ee53b27cc9c1d0559e8baafb43f5
        module_layout=module_memory
        module_relative=usr/lib/modules/$release/kernel/virt/lib/irqbypass.ko.xz
        module_compression=xz
        ;;
    6.12-arm64)
        architecture=aarch64
        release=6.12.105+deb13-cloud-arm64
        image_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux-signed-arm64/linux-image-6.12.105+deb13-cloud-arm64_6.12.105-1_arm64.deb
        image_sha=db60fd4b4458254b824baccfb4abe46fee5a999cb1e61a493d927955bdf343da
        debug_url=https://deb.debian.org/debian-security/pool/updates/main/l/linux/linux-image-6.12.105+deb13-cloud-arm64-dbg_6.12.105-1_arm64.deb
        debug_sha=bc014dcb589b987e202166a79c51f969d872a8d95389ffeb16f7a396fca596da
        busybox_url=https://deb.debian.org/debian/pool/main/b/busybox/busybox-static_1.37.0-6+b8_arm64.deb
        busybox_sha=6d144e5012d47ec3a6f2102ba6fac644ad34c989373fed30c1bb7264f5cd3616
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
