#!/bin/bash
#
# Produce a deb source package that can be uploaded to a Debian/Ubuntu builder.

if [[ $(git --no-optional-locks status -uno --porcelain) ]]; then
    echo "ERROR: git repository is not clean"
    exit 1
fi

# Stop on error
set -e

BPFTOOL=$(ls -c1 /usr/lib/linux-*tools*/bpftool 2>/dev/null | sort -n | tail -1)

# Fetch Rust dependencies for offline build
meson setup build -Dcargo_home=`pwd`/cargo-deps
meson compile -C build fetch

# Clean-up binary artifacts from embedded repos
cd build/libbpf
rm -f assets/*
rm -f fuzz/bpf-object-fuzzer_seed_corpus.zip
rm -rf .git
cd -
cd build/bpftool/libbpf
rm -f assets/*
rm -f fuzz/bpf-object-fuzzer_seed_corpus.zip
rm -rf .git
cd -
cd build/bpftool
rm -rf .git
cd -

# Add and commit all the embedded build dependencies
git add -f build
git add -f cargo-deps
git commit -sm "DROP THIS: include dependencies"

# Create upstream tag (required by gbp)
version=$(dpkg-parsechangelog -SVersion | cut -d- -f1)
git tag -f upstream/${version}

# Produce source package (including an orig tarball)
git clean -xdf
git reset --hard HEAD
gbp buildpackage --git-ignore-branch -S -sa --lintian-opts --no-lintian
git clean -xdf
git reset --hard HEAD
