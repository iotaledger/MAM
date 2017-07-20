#!/bin/bash

c=/tmp/libiota_mam_bindings.a
cb=`ar t $c | grep compiler`

ar x $c $cb

arm-none-eabi-objcopy -N __aeabi_dadd $cb
arm-none-eabi-objcopy -N __aeabi_dsub $cb
arm-none-eabi-objcopy -N __aeabi_fsub $cb
arm-none-eabi-objcopy -N __aeabi_fadd $cb
arm-none-eabi-objcopy -N __aeabi_ui2f $cb
arm-none-eabi-objcopy -N __aeabi_i2f $cb
arm-none-eabi-objcopy -N __aeabi_ui2d $cb
arm-none-eabi-objcopy -N __aeabi_i2d $cb
arm-none-eabi-objcopy -N __aeabi_ul2d $cb
arm-none-eabi-objcopy -N __aeabi_l2d $cb

ar r $c $cb
rm $cb
