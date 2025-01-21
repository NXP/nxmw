# Enable Certificate Cache Example

This project demonstrates the operation of the host and Secure Authenticator certificate cache, including enabling the Secure Authenticator certificate cache using Nx APIs.
Enabling the certificate cache accelerates protocol execution by skipping the verification of certificates that have already been verified.

Refer [**Certificate cache Example file**](./ex_sss_cert_cache.c)

## Prerequisites

- Clear the host cache file.

## About the Example

This example demonstrates enabling the certificate cache. If a certificate has been previously verified and is present in the cache, the verification process will be skipped. The steps in this example are as follows:

- Set up Sigma-I session 1 with CMake host cache enabled and exchange the certificate chain.
- Enable the Sigma-I certificate cache on the Secure Element (SE).
- Close session 1.
- Save the certificate in the host cache file.
- Set up Sigma-I session 2 with host certificate cache enabled. Since the Secure Authenticator's certificate hash
  and signature
  are cached, the host will not require certificates from the Secure Authenticator. Similarly,
  the Secure Authenticator will not require certificates from the host.
- Close session2 .

The example uses the following APIs and data types:

- `sss_session_close()`
- `nx_SetConfig_CertMgmt()`
- `sss_session_open()`


## Building the Example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).

	- `NXMW_Auth=SIGMA_I_Verifier` or `NXMW_Auth=SIGMA_I_Prover`
	- `NXMW_Auth_Asymm_Host_PK_Cache=Enabled`
	- Project - `ex_cert_cache`

## Console Output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :INFO :Session 2 open succeed by certificate cache
App   :INFO :Close session 2
App   :INFO :ex_sss_cert_cache Example Success !!!…
App   :INFO :ex_sss Finished
```
