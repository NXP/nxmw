# Certificate Repository Example

This project demonstrates generating a certificate repository using SSS and Nx APIs. It will create repository, load certificate and mapping
table and activate the repository.

Refer [**Certificate Repo Example**](./ex_sss_cert_repo.c)

## About the Example

This example creates a certificate repository and loads certificate chain into it. In detail:
-   Set ECC private key associated with the repository.
-   Create a certificate repository.
-   Load certificate chains (Leaf, Parent and Grand Parent certificate)into repository.
-   Load Mapping table into repository. This step is optional and only required when using host certificate
    wrapping e.g. PKCS#7. The wrapping basically provides a path, using ASN.1 encoding, to the start of the x.509 certificate.
-   Activate repository.

The example uses the following APIs and data types:

- `sss_key_object_init()`
- `sss_key_object_allocate_handle()`
- `sss_key_store_set_key()`
- `sss_key_object_free()`
- `nx_ManageCertRepo_CreateCertRepo()`
- `nx_ManageCertRepo_LoadCert()`
- `nx_ManageCertRepo_LoadCertMapping()`
- `nx_ManageCertRepo_ActivateRepo()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	-  Select NXMW_Auth to SIGMA_I\_Verifier, SIGMA_I\_Prover or SYMM_Auth
	-  NXMW_Secure_Tunneling to NTAG_AES128_EV2, NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2 (only with SIGMA_I\_Verifier or
	   SIGMA_I\_Prover)
	-  The authentication must be setup with access condition 0. This means App Master key for symmetric authentication.
	   For Sigma-I authentication, this mean AC0 of certificate access right. It is defined with CA root key and reader certificate (or certificate chain).
	- project - `ex_cert_repo`


## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Set ECC private key (3) associated with this repository.
App   :INFO :Load device leaf certificate Successful !!!
App   :INFO :Load device P1 certificate Successful !!!
App   :INFO :Load device P2 certificate Successful !!!
App   :INFO :Load leaf certificate mapping table for PKCS#7 wrapping Successful !!!
App   :INFO :Load P1 certificate mapping table for PKCS#7 wrapping Successful !!!
App   :INFO :Load P2 certificate mapping table for PKCS#7 wrapping Successful !!!
App   :INFO :Activate certificate repository Successful !!!
App   :INFO :ex_sss_cert_repo Example Success !!!...
App   :INFO :ex_sss Finished
```

