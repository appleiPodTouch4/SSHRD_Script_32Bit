#!/bin/bash
echo "32-bit Bruteforce SSH Ramdisk by meowcat454,AJAIZ and platinumstuff"
echo "--------------------------------"
echo "RAMDISK SETUP: STARTING" > /dev/console

# remount r/w
echo "RAMDISK SETUP: REMOUNTING ROOTFS" > /dev/console
mount -o rw,union,update /

# free space
#rm /usr/local/standalone/firmware/*
#rm /usr/standalone/firmware/*
#mv /sbin/reboot /sbin/reboot_bak

# Fix the auto-boot
echo "RAMDISK SETUP: SETTING AUTOBOOT" > /dev/console
nvram auto-boot=1

# Start SSHD
echo "RAMDISK SETUP: STARTING SSHD" > /dev/console
/sbin/sshd

# Run restored_external
echo "RAMDISK SETUP: COMPLETE" > /dev/console
/usr/local/bin/restored_external.sshrd > /dev/console

echo "Mounting Partitions..." > /dev/console
/bin/mount.sh > /dev/console

echo "Starting bruteforce..." > /dev/console
/usr/bin/bruteforce -u > /dev/console

echo "When it finished, the last one is the password."
echo "Use ./sshrd32.sh --reboot or home + power button to reboot device "