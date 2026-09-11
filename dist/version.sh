#!/bin/sh
# Prints the package version for the current checkout: the tag without its
# leading v when HEAD is tagged vX.Y.Z, otherwise a 0.0.0 snapshot version
# that sorts below any release. Takes "deb" or "arch" for the snapshot syntax.
set -e
tag=$(git describe --tags --exact-match 2>/dev/null || true)
case "$tag" in
v[0-9]*) echo "${tag#v}"; exit 0 ;;
esac
count=$(git rev-list --count HEAD)
sha=$(git rev-parse --short HEAD)
case "${1:-deb}" in
deb)  echo "0.0.0+git$count.$sha" ;;
arch) echo "0.0.0.r$count.g$sha" ;;
*) echo "usage: version.sh deb|arch" >&2; exit 2 ;;
esac
