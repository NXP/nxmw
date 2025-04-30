Overview
========

This project allows the Kinetis FRDM-K64F board to be used as a
bridge between the PC and the Secure Authenticator and enables the execution of the demos/applications from the PC.

As a system how the integrated system looks like is as follows:

    +--------------------+          +---------------------+
    |        PC          |          |   Kinetis (USB)     |
    |--------------------|          |---------------------|
    |                    |          |  Test App with USB  |
    | - NX Application   |          |  VCOM-CDC Interface |
    |    or Demo         |          |                     |
    |                    |          |                     |
    |         OR         |          |  +---------------+  |
    |                    |          |  |      APDU     |  |
    |                    |          |  +---------------+  |
    | - mbed TLS Test    |   VCOM   |  +---------------+  |
    |    Applications    +----------+  |  SmComT1oI2C  |  |
    |                    |          |  +---------------+  |
    |                    |          |  +---------------+  |
    |                    |          |  |  i2c_kinetis  |  |
    |                    |          |  +---------------+  |
    |                    |          |  +---------------+  |
    |                    |          |  |     i2c       |  |
    |                    |          |  +---------------+  |
    +--------------------+          +---------+-----------+
                                              |
                                              | I2C Interface
                                              |
                                    +---------+------------+
                                    |      NX Secure       |
                                    |    Authenticator     |
                                    +----------------------+

Toolchain supported
===================
- MCUXpresso
- Keil
- IAR

Hardware requirements
=====================
- Micro USB cable (2)
- Kinetis FRDM-K64F board
- Personal Computer
- NX Secure Authenticator
- NX Secure Authenticator shield

Board settings
==============
No special settings are required.

Prepare the Demo
================
1. Build the demo
2. Connect a USB cable between the PC host and the OpenSDA USB port on the
   target board.
3. Connect a USB cable between the PC host and the VCOM USB port on the target
   board.
4. Download the program to the target board.
5. Either press the reset button on your board or launch the debugger in your
   IDE to begin running the demo.

Running the demo
================
The config tool or other utilities can now be executed from the PC and the
functionalities of the secure module are invoked via the VCOM bridge.

End of project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
