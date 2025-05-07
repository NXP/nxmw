# Porting to New Host Crypto

NX middleware by default provides support for mbedTLS and OpenSSL host crypto via SSS APIs.
The host crypto is used during session open phase and for any other crypto operations required later.
The section describes the steps required for porting middleware to new host crypto.


## OPTION-1

If the new host crypto is **only** required for session open phase, re-implement the functions in :file:`nxmw/lib/sss/src/nx/fsl_sss_nx_auth_host.c` file for new crypto. (The file is currently ported to OpenSSL and mbedTLS crypto).


## OPTION-2

A new host crypto can be added by re-implementing the SSS APIs and updating the cmake options.

Follow the below steps -

Add an entry for new host crypto in the **cmake_options.py** file as shown

```
    *** <ROOT-DIR>\nxmw\scripts\cmake_options.py ***

      LIST_HOSTCRYPTO = [
        ("MBEDTLS", "Use mbedTLS as host crypto", True),
        ("OPENSSL", "Use OpenSSL as host crypto", True),

        < NEW ENTRY>

        ("None",
         ("NO Host Crypto",
          "Note,  the security of configuring Nx to be used without HostCrypto",
          "needs to be assessed from system security point of view"

          ), True),
    ]
```

Run python cmake_options.py from the same location ::

```
cd nxmw/scripts
python cmake_options.py
```

Other files in the **<ROOT-DIR>\\nxmw\\scripts** folder and feature file :file:`fsl_sss_ftr.h` are updated by this new option.

**Rebuild** the project and the build folder's CMake would now reflect this newly added CMake variable. Example -

```
cd nxmw_build/nxmw-eclipse_arm
cmake .
```

Create new sss host crypto module in `sss` folder - :file:`nxmw/lib/sss/src/<NEW_CRYPTO>/<new_crypto>.c`

Include the same in cmake file - :file:`nxmw/lib/sss/CMakeLists.txt`

```
  PROJECT(SSS_APIs LANGUAGES C)

  FILE(
      GLOB
      API_FILES
      inc/*.h
      inc/*.h.in
      src/*.c
      src/nx/*.c
      src/mbedtls/*.c
      src/openssl/*.c
      *<NEW_CRYPTO>/<new_crypto>.c*
      src/keystore/*.c
      port/default/*.h
  )
```

Refer - :file:`nxmw/lib/sss/src/mbedtls/fsl_sss_mbedtls_apis.c` or :file:`nxmw/lib/sss/src/openssl/fsl_sss_openssl_apis.c`.

