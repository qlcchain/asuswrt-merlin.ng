# Building Instruction

The Building Instruction on MerLin official website is not update recently. Thanks to  [Fitz Mutch](https://www.snbforums.com/members/fitz-mutch.48408/) provide the [script](https://www.snbforums.com/threads/merlinwrt-compile-instructions.47984/page-3) on Ubuntu 18.04.

### Install fresh Ubuntu 18.04 LTS (Bionic Beaver)
ubuntu-18.04.1-desktop-amd64.iso


### Apply OS updates and make bash the default shell (reboot required)
`sudo apt-get update && sudo apt-get -y dist-upgrade && sudo rm -f /bin/sh && sudo ln -sf bash /bin/sh && sudo reboot`


### Install Linux kernel headers and essential development tools
`sudo apt-get update && sudo apt-get -y install git build-essential linux-headers-$(uname -r)`


### Install dependencies for AsusWRT
`sudo dpkg --add-architecture i386 && sudo apt-get update && sudo apt-get -y install libtool-bin cmake libproxy-dev uuid-dev liblzo2-dev autoconf automake bash bison bzip2 diffutils file flex m4 g++ gawk groff-base libncurses5-dev libtool libslang2 make patch perl pkg-config shtool subversion tar texinfo zlib1g zlib1g-dev git gettext libexpat1-dev libssl-dev cvs gperf unzip python libxml-parser-perl gcc-multilib gconf-editor libxml2-dev g++-multilib gitk libncurses5 mtd-utils libncurses5-dev libvorbis-dev git autopoint autogen sed build-essential intltool libelf1 libglib2.0-dev xutils-dev lib32z1-dev lib32stdc++6 xsltproc gtk-doc-tools libelf-dev:i386 libelf1:i386 libltdl-dev libsysfs-dev`


### Clone the toolchains
`git clone https://github.com/RMerl/am-toolchains`

### Fix the toolchain symlinks
`sudo mkdir -p /opt ; sudo rm -rf /opt/toolchains ; sudo ln -s ~/am-toolchains/brcm-arm-hnd /opt/toolchains ; sudo rm -f /opt/brcm-arm ; sudo ln -s ~/am-toolchains/brcm-arm-sdk/hndtools-arm-linux-2.6.36-uclibc-4.5.3 /opt/brcm-arm ; sudo rm -f /opt/brcm ; sudo ln -s ~/am-toolchains/brcm-mips-sdk/tools/brcm /opt/brcm`


### Clone the repo
`git clone https://github.com/qlcchain/asuswrt-merlin.ng.git`

# fix symlinks for HND toolchain
`rm -rf ~/asuswrt-merlin.ng-build/release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/toolchains`

`ln -s ~/am-toolchains/brcm-arm-hnd ~/asuswrt-merlin.ng-build/release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/toolchains`

# fix symlinks for ARM toolchain
`rm -rf ~/asuswrt-merlin.ng-build/release/src-rt-6.x.4708/toolchains`

`ln -s ~/am-toolchains/brcm-arm-sdk ~/asuswrt-merlin.ng-build/release/src-rt-6.x.4708/toolchains`


### Build RT-AC86U firmware (HND)
`export LD_LIBRARY_PATH=/opt/toolchains/crosstools-arm-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/lib`

`export TOOLCHAIN_BASE=/opt/toolchains`

`echo $PATH | grep -qF /opt/toolchains/crosstools-arm-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/bin || export PATH=$PATH:/opt/toolchains/crosstools-arm-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/bin`

`echo $PATH | grep -qF /opt/toolchains/crosstools-aarch64-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/bin || export PATH=$PATH:/opt/toolchains/crosstools-aarch64-gcc-5.3-linux-4.1-glibc-2.22-binutils-2.25/usr/bin`

`cd ~/asuswrt-merlin.ng-build/release/src-rt-5.02hnd`

`make rt-ac86u`


### Build RT-AC68U firmware (ARM)
`export LD_LIBRARY_PATH=`

`export TOOLCHAIN_BASE=`

`echo $PATH | grep -qF /opt/brcm-arm/bin || export PATH=$PATH:/opt/brcm-arm/bin`

`echo $PATH | grep -qF /opt/brcm-arm/arm-brcm-linux-uclibcgnueabi/bin || export PATH=$PATH:/opt/brcm-arm/arm-brcm-linux-uclibcgnueabi/bin`

`cd ~/asuswrt-merlin.ng-build/release/src-rt-6.x.4708`

`make rt-ac68u`


### Build RT-AC88U firmware (ARM)
`export LD_LIBRARY_PATH=`

`export TOOLCHAIN_BASE=`

`echo $PATH | grep -qF /opt/brcm-arm/bin || export PATH=$PATH:/opt/brcm-arm/bin`

`echo $PATH | grep -qF /opt/brcm-arm/arm-brcm-linux-uclibcgnueabi/bin || export PATH=$PATH:/opt/brcm-arm/arm-brcm-linux-uclibcgnueabi/bin`

`cd ~/asuswrt-merlin.ng-build/release/src-rt-7.14.114.x/src`

`make rt-ac88u`

if there is compile err, you might need to install the different version of autoconf
