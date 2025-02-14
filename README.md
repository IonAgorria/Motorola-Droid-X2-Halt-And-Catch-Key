# Motorola Droid X2 - Halt And Catch Key

Kernel module for Motorola Droid X2 / motorola_daytona to load payload and enter RCM for extracting the device's SBK.

## Why?

With this key the use of RCM bootrom recovery and full ownership of device can be archieved.

These devices lack bootloader unlock as the Motorola Atrix 4G thus the only way is to do is rooting the device and
running code in the kernel to setup hardware ready for triggering the exploit.

## Usage

A prebuilt module for `Android 2.3.5` `VRZ_MB870_4.5.1A-DTN-200-18_1FF_01` has been provided as `daytona_hack_2.6.32.9-00008-gc40630.ko`

If you don't wish to flash it you can try to build module for your kernel version.

- Have root shell in device with terminal app so you can type shell commands on device
- Copy .ko kernel module to device
- Plug Factory cable to device (USB cable with ID shorted to VBUS, this tells device to connect the other USB controller to USB port)
- Run command `insmod "/data/daytona_hack.ko"`
- Device should be now in APX/RCM mode, use fusee-gelee to trigger exploit with --skip-upload

## Building

- CROSS_COMPILE used: `arm-linux-androideabi-4.6/bin/arm-linux-androideabi-`
- Use the following stock kernel sources: `https://sourceforge.net/projects/mb870.motorola/files/Droidx2_VZW/DTN_150.30/`
- Put this repo inside kernel source's as `drivers/daytona_hack`
- Add `obj-y += daytona_hack/` to `drivers/Makefile`
- Edit kernel's `Makefile` so that module's vermagic matches your device's kernel and module is loadable
- Run `make modules`
- It should generate drivers/daytona_hack/daytona_hack.ko
