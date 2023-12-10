#!/bin/bash
#
# Produce a deb source package that can be uploaded to a Debian/Ubuntu builder.

if [[ $(git --no-optional-locks status -uno --porcelain) ]]; then
    echo "ERROR: git repository is not clean"
    exit 1
fi

# Stop on error
set -e

# Fetch Rust dependencies for offline build
meson setup build -Dcargo_home=`pwd`/cargo-deps
meson compile -C build fetch

# Commit all Rust dependencies in cargo-deps
git add cargo-deps
git commit -sm "include Rust dependencies"

# Create upstream tag (required by gbp)
version=$(dpkg-parsechangelog -SVersion | cut -d- -f1)
git tag -f upstream/${version}

# Produce source package (including an orig tarball)
git clean -xdf
git reset --hard HEAD
gbp buildpackage --git-ignore-branch -S -sa --lintian-opts --no-lintian
git clean -xdf
git reset --hard HEAD
