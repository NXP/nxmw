# Counter File Example

This project demonstrates counter file operations using Nx APIs.

Refer [**Counter File Example**](./ex_sss_counter_file.c)

## About the Example

This example does following:

- Creates a counter file (file No is 5)
- Gets current counter value
- Increases counter by 3
- Gets current counter value

It uses the following APIs and data types:

- `nx_CreateCounterFile()`
- `nx_GetFileCounters()`
- `nx_IncrCounterFile()`

## Building the Example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).

	- Project: `ex_counter_file`
	- SIGMA_I_Verifier or SIGMA_I_Prover or SYMM_Auth should be used for NXMW_Auth.
	- Due to the authentication requirement for nx_CreateCounterFile(), this demo should be run with access condition 0 (App Master Key)


## Console output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :INFO :Running File Management Example ex_sss_counter_file.c
App   :INFO :Counter File creation successful !!!
App   :INFO :Current counter value is 0x0
App   :INFO :Increase counter by 0x3
App   :INFO :Current counter value is 0x3
App   :INFO :ex_sss_counter_file Example Success !!!...
App   :INFO :ex_sss Finished
```

