..
    Copyright 2024 NXP



.. highlight:: bat

.. _ex-nx-t1oi2c:

=======================================================================
T1oI2C example
=======================================================================

This project is used to demonstrate the usage of T1oI2C APIs.
The example will send a command to get available memory from Secure Authenticator.

Prerequisites
=======================================================================

- Nx middleware stack. (Refer :ref:`building`)

About the Example
=======================================================================
This project gets available memory from Secure Authenticator using T1oI2C APIs.

It uses the following API:
  - :cpp:func:`phNxpEse_open()`
  - :cpp:func:`phNxpEse_init()`
  - :cpp:func:`phNxpEse_Transceive()`
  - :cpp:func:`phNxpEse_EndOfApdu()`
  - :cpp:func:`phNxpEse_close()`

Building the Example
=======================================================================

- Project: ``ex_t1oi2c``

1) select NXMW_Host to PCLinux64 or Raspbian

2) select NXMW_SMCOM to T1oI2C_GP1_0

Since this is a "tloi2c" example, it will work over a plain session without setting up any authenticated session.

Refer :numref:`se-cmake-options` --- :ref:`se-cmake-options`

Console output
=======================================================================

If everything is successful, the output will be similar to:

.. literalinclude:: out_nx_t1oi2c.rst.txt