#!/bin/sh
set -eu

version=$1
sha256=$2
prefix=$3

if [ -x "$prefix/bin/gdb" ]; then
    "$prefix/bin/gdb" --version | head -n 1
    exit 0
fi

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
archive="$build_dir/gdb-$version.tar.xz"

curl -fsSL --retry 3 \
    "https://mirrors.kernel.org/gnu/gdb/gdb-$version.tar.xz" \
    -o "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum -c -
tar -xf "$archive" -C "$build_dir"
# 2026-09-05: GDB 9 through 13 use a 2696-byte XSAVE buffer and can fail
# register restoration when the host layout exceeds it. Widen only that
# legacy scratch buffer so the historical MI implementations remain testable.
# ponytail: 16 KiB covers current x86 CI; backport CPUID sizing if it grows.
for xstate_header in \
    "$build_dir/gdb-$version/gdbsupport/x86-xstate.h" \
    "$build_dir/gdb-$version/gdb/gdbsupport/x86-xstate.h"
do
    if [ -f "$xstate_header" ] \
        && grep -q '^#define X86_XSTATE_MAX_SIZE[[:space:]]*2696$' "$xstate_header"
    then
        sed -i \
            's/^#define X86_XSTATE_MAX_SIZE[[:space:]]*2696$/#define X86_XSTATE_MAX_SIZE 16384/' \
            "$xstate_header"
    fi
done
mkdir "$build_dir/obj"
cd "$build_dir/obj"

"../gdb-$version/configure" \
    --prefix="$prefix" \
    --disable-binutils \
    --disable-gas \
    --disable-gold \
    --disable-gprof \
    --disable-ld \
    --disable-sim \
    --disable-tui \
    --disable-werror \
    --with-expat \
    --with-system-readline \
    --without-guile \
    --without-python
make -j2 all-gdb
make install-gdb
"$prefix/bin/gdb" --version | head -n 1
