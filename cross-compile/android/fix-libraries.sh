#!/bin/sh

set -e
tmpdir=/tmp/fixlib$$
trap 'rm -rf "$tmpdir"' 0 1 2 3 15
mkdir -p "$tmpdir"

if [ $# -lt 3 ]; then
  echo >&2 "Usage: $0 srclib destlib library ..."
  exit 1
fi

: ${READELF=readelf}

srclib="$1"
destlib="$2"
shift
shift
rm -f "$tmpdir"/todo
touch "$tmpdir"/todo
for lib; do
  echo "$lib" >> "$tmpdir"/todo
done

process()
{
  libname="$1"
  libfile="$destlib"/"$libname"
  if [ ! -f "$libfile" ]; then
    echo >&2 "$libfile not found"
    exit 1
  fi
  "$READELF" -d "$libfile" | awk '$1=="0x00000001" {print $NF}' | tr -d '][' | grep '\.so\.' | sort >> "$tmpdir"/worklist
}

install()
{
  libname="$1"
  libfile=`echo "$libname" | sed -e 's/\.so\..*/.so/'`
  cp "$srclib"/"$libname" "$destlib"/"$libfile"
  echo "$libfile" >> "$tmpdir"/worklist
  for deplib in `"$READELF" -d "$destlib"/"$libfile" | awk '$1=="0x00000001" {print $NF}' | tr -d '][' | grep '\.so\.' | sort`; do
    echo "$deplib $libname"  >> "$tmpdir"/liblist
  done
}

rm -f "$tmpdir"/liblist
touch "$tmpdir"/liblist
sort "$tmpdir"/todo > "$tmpdir"/processed
while [ -s "$tmpdir"/todo ]; do
  rm -f "$tmpdir"/worklist
  touch "$tmpdir"/worklist
  cat "$tmpdir"/todo | while read lib; do
    if [ ! -z "$lib" ]; then
      process "$lib"
    fi
  done
  sort "$tmpdir"/worklist | uniq > "$tmpdir"/todo.tmp
  comm -13 "$tmpdir"/processed "$tmpdir"/todo.tmp > "$tmpdir"/todo
  sort -m "$tmpdir"/processed "$tmpdir"/todo | uniq > "$tmpdir"/processed.tmp
  mv "$tmpdir"/processed.tmp "$tmpdir"/processed
  rm -f "$tmpdir"/worklist
  touch "$tmpdir"/worklist
  cat "$tmpdir"/todo | while read lib; do
    if [ ! -z "$lib" ]; then
      install "$lib"
    fi
  done
  mv "$tmpdir"/worklist "$tmpdir"/todo
done
tsort "$tmpdir"/liblist
