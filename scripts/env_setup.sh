#
# Copyright 2018,2019 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

CROSS_COMPILE=arm-none-eabi-

# From latest to oldest down.

# 1) Ubuntu

if [ -e /usr/local/mcuxpressoide/ide/ ]; then
    MCU_ROOT=/usr/local/mcuxpressoide/ide/

# 2) MSYS Windows

elif [ -e /c/nxp/MCUXpressoIDE_11.2.0_4120/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.2.0_4120/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.1.1_3241/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.1.1_3241/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.0.1_2563/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.0.1_2563/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.0.0_2516/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.0.0_2516/ide/
elif [ -e /c/nxp/MCUXpressoIDE_10.3.0_2200/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_10.3.0_2200/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.1.0_3209/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.1.0_3209/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.3.0_5222/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.3.0_5222/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.3.1_5262/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.3.1_5262/ide/
elif [ -e /c/nxp/MCUXpressoIDE_11.4.0_6237/ide/ ]; then
    MCU_ROOT=/c/nxp/MCUXpressoIDE_11.4.0_6237/ide/

# 3) WSL

elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.2.0_4120/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.2.0_4120/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.1.1_3241/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.1.1_3241/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.0.1_2563/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.0.1_2563/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.0.0_2516/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.0.0_2516/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_10.3.0_2200/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_10.3.0_2200/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.1.0_3209/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.1.0_3209/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.3.0_5222/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.3.0_5222/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.3.1_5262/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.3.1_5262/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.4.0_6237/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.4.0_6237/ide/
elif [ -e /mnt/c/nxp/MCUXpressoIDE_11.6.0_8187/ide/ ]; then
    MCU_ROOT=/mnt/c/nxp/MCUXpressoIDE_11.6.0_8187/ide/

# 4) DARWIN

elif [ -e /Applications/MCUXpressoIDE_11.2.0_4120/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.2.0_4120/ide/
elif [ -e /Applications/MCUXpressoIDE_11.1.1_3241/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.1.1_3241/ide/
elif [ -e /Applications/MCUXpressoIDE_11.0.1_2563/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.0.1_2563/ide/
elif [ -e /Applications/MCUXpressoIDE_11.0.0_2516/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.0.0_2516/ide/
elif [ -e /Applications/MCUXpressoIDE_10.2.1_795/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_10.2.1_795/ide/
elif [ -e /Applications/MCUXpressoIDE_11.3.0_5222/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.3.0_5222/ide/
elif [ -e /Applications/MCUXpressoIDE_11.3.1_5262/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.3.1_5262/ide/
elif [ -e /Applications/MCUXpressoIDE_11.4.0_6237/ide/ ]; then
    MCU_ROOT=/Applications/MCUXpressoIDE_11.4.0_6237/ide/

# 5) Cygwin

elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.2.0_4120/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.2.0_4120/ide/
elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.1.1_3241/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.1.1_3241/ide/
elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.0.1_2563/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.0.1_2563/ide/
elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.0.0_2516/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.0.0_2516/ide/
elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.3.0_5222/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.3.0_5222/ide/
elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.3.1_5262/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.3.1_5262/ide/
elif [ -e /cygdrive/c/nxp/MCUXpressoIDE_11.4.0_6237/ide/ ]; then
    MCU_ROOT=/cygdrive/c/nxp/MCUXpressoIDE_11.4.0_6237/ide/
else
    echo -e "MCU_ROOT Not detected. Install Mcuxpresso and/or update $BASH_SOURCE to point to it."
fi

if [ -e ${MCU_ROOT} ]; then
    echo "# Using MCUXPresso from ${MCU_ROOT} for Kinetis/LPC/iMX.RT Controllers"
fi

if [ -e "/c/Program Files/doxygen/bin" ]; then
    PATH="${PATH}:/c/Program Files/doxygen/bin"
fi

if [ -e /usr/local/android-ndk-r18b-linux-x86_64/android-ndk-r18b ]; then
    export ANDROID_NDK_ROOT=/usr/local/android-ndk-r18b-linux-x86_64/android-ndk-r18b
    echo -e "Android Ndk root set to :$ANDROID_NDK_ROOT"
fi

if [ -e /c/Python37 ]; then
    PATH=/c/Python37:/c/Python37/Scripts:$PATH
fi

if [ -e /c/opt/cmake/bin/cmake.exe ]; then
    PATH=/c/opt/cmake/bin:$PATH
fi

if [ -e ${MCU_ROOT}/tools ]; then
    ARMGCC_DIR=${MCU_ROOT}tools
    PATH=${MCU_ROOT}bin:${PATH}:${MCU_ROOT}
fi

if [ -e ${ARMGCC_DIR} ]; then
    PATH=${ARMGCC_DIR}/bin:${PATH}
fi

# MSYS Windows
if [ -e "/c/Program Files/Java/jdk1.8.0_291" ]; then
    export JAVA_HOME="/c/Program Files/Java/jdk1.8.0_291"
elif [ -e "/c/Program Files/Java/jdk1.8.0_201" ]; then
    export JAVA_HOME="/c/Program Files/Java/jdk1.8.0_201"
elif [ -e "/c/Program Files/Java/jdk1.8.0_191" ]; then
    export JAVA_HOME="/c/Program Files/Java/jdk1.8.0_191"
elif [ -e "/c/Program Files/Java/jdk1.8.0.362-1" ]; then
    export JAVA_HOME="/c/Program Files/Java/jdk1.8.0.362-1"

# WSL
if [ -e "/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0_291" ]; then
    export JAVA_HOME="/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0_291"
elif [ -e "/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0_201" ]; then
    export JAVA_HOME="/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0_201"
elif [ -e "/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0_191" ]; then
    export JAVA_HOME="/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0_191"
elif [ -e "/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0.362-1" ]; then
    export JAVA_HOME="/mnt/c/'Program Files'/RedHat/java-1.8.0-openjdk-1.8.0.362-1"
fi
echo -e "JAVA_HOME is set to :$JAVA_HOME"

# CXX=${CROSS_COMPILE}gcc
# CC=${CROSS_COMPILE}gcc
# AR=${CROSS_COMPILE}gcc-ar

export PATH ARMGCC_DIR
