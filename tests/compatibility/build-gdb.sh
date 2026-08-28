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
