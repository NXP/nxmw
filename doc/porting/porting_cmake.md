# New Platform Support Using Cmake Build

This sections explains the process of adding new platform support using cmake build system.
The root of the middleware contains the **boards** folder and the new platform files need to be added in here,

```
nxmw
   |
   boards
      |
      ├── frdmmcxa153 ----- FRDM MCXA 153 specific files.
      |
      ├── frdmmcxn947 ----- FRDM MCXN 947 specific files.
      |
      ├── generic ------ Wrappers for timer implementation.
      |
      ├── inc
      |
      ├── ksdk --------- Common functions of KSDK.
      |
      ├── linux -------- Linux specific files.
      |

```

The following steps describe the process to add new micro-controller support.

>**Note:** We will consider lpc55s69 as a new controller.


## Add new host platform in cmake build options

Add an entry for imx-rt in the **cmake_options.py** file as shown

```
*** <ROOT-DIR>\nxmw\scripts\cmake_options.py ***

  LIST_HOST = [
    ("PCWindows", "PC/Laptop Windows", True),
    ("PCLinux64", "PC/Laptop Linux64", True),
    ("lpcxpresso55s", "Embedded LPCXpresso55s", True),
    ("Raspbian", "Embedded Linux on RaspBerry PI", True),
    ("frdmmcxa153", "Embedded frdmmcxa153", True),
    ("frdmmcxn947", "Embedded frdmmcxn947", True),
]
```

Run python cmake_options.py from the same location. This will update the cmake options with new host platform option ::

```
cd nxmw\scripts
python cmake_options.py
```

**Rebuild** the project (if already created one) as

```
  cd nxmw_build/nxmw-eclipse_arm
  cmake .
```

This will update the feature file with new platform macro -

```
/** Embedded LPCXpresso55s */
#define SSS_HAVE_HOST_LPCXPRESSO55S 0
```

Also do a manual update to :file:`nxmw/scripts/cmake_options.cmake` file to add an entry for new micro-controller. Example -

```
ELSEIF(SSS_HAVE_HOST_LPCXPRESSO55S)
  SET(SSS_HAVE_KSDK ON)
  SET(KSDK_BoardName "lpcxpresso55s69")
  SET(KSDK_CPUName "LPC55S69")
```


A new cmake file defining the linker options of new platform needs to be added. Example - ksdk_lpcxpresso55s.cmake.

Include the same in :file:`nxmw/scripts/ksdk.cmake`


## Updating boards folder

Add new platform folder in boards directory (say lpcxpresso55s69). This should match the board name added in cmake_options.cmake file.
Copy / implement the necessary files here. (Refer existing frdmmcxn947 folder).

Refer :file:`nxmw/boards/frdmmcxn947/CMakeLists.txt` and create a new cmake file - :file:`nxmw/boards/lpcxpresso55s69/CMakeLists.txt` to include the relevant files of new platform from the mcu-sdk and boards dir. Ensure that I2C driver is implemented properly. (Refer existing frdmmcxn947 folder for required files and implementation).

For more information on existing projects using cmake build refer: [**CMake Projects for NX SA**](../../doc/mcu_cmake/readme.md).