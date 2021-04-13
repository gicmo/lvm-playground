#!/bin/bash
set -x

dd if=/dev/zero of=image.img bs=512 count=$(( 100 * 1024 * 2 ))
sudo losetup /dev/loop0 image.img
sudo pvcreate /dev/loop0
sudo vgcreate vg_test /dev/loop0
sudo lvcreate --noudevsync -n lv_test1 -L 50M vg_test
sudo losetup -d /dev/loop0
mv image.img /shared