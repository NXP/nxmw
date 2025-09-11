# Secure Authenticator APIs Reference Documentation

## SSS APIs

	SSS is an acronym for Secure Sub System.
	The SSS APIs are functional APIs to abstract the access to various types of Cryptographic Sub Systems. Such secure
	subsystems could be (but not limited to):
	- Secure Authenticator
	- Secure Enclaves
	- Cryptographic HWs

- fsl_sss_api.h 

## NX APIs

	NX APIs are a set of standardized interfaces provided by a secure authenticator that allow secure communication, cryptographic operations, and key management between a host processor and a secure authenticator.

- nx_apdu.h