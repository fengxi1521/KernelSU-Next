#!/bin/sh

TMPDIR=/dev/tmp
rm -rf $TMPDIR
mkdir -p $TMPDIR 2>/dev/null

ARCH="$(getprop ro.product.cpu.abi)"
OUTFD=/proc/self/fd/$2

ui_print() {
  echo -e "ui_print $1\nui_print" >> $OUTFD
}

if [ ! "$ARCH" = "arm64-v8a" ]; then
    ui_print "- Unsupported architecture: $ARCH"
    exit 1
fi

# Extract xfgd
unzip -o "$3" "lib/$ARCH/libxfgd.so" -d $TMPDIR >&2

XFGD="$TMPDIR/lib/$ARCH/libxfgd.so"

chmod 755 "$XFGD"

# use xfgd to install or uninstall
case "$3" in
  *uninstall*|*Uninstall*)
    ui_print "- Uninstalling XiaoFeng..."
    "$XFGD" uninstall 2>&1 | while read -r line; do
      ui_print "$line"
    done
    ;;
  *)
    ui_print "- Installing XiaoFeng..."
    "$XFGD" boot-patch --flash 2>&1 | while read -r line; do
      ui_print "$line"
    done
    ;;
esac

true
