#!/usr/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

# called by dracut
check() {
    return 0
}
# called by dracut
install() {
    inst_hook initqueue 63 "$moddir/svm-rootfs-hook.sh"
    inst_multiple svm-rootfs-askpass nc esmb-get-file cryptsetup
}
