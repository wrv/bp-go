## Bulletproofs in Go

This project implements Bulletproofs in Go. More information about Bulletproofs
can be found [here](https://crypto.stanford.edu/bulletproofs/)

Paper references for the steps of the protocol:
- The inner-product argument is implemented as shown in Protocol 1 and Protocol 2.
- The range proof is implemented as described in Section 4.1.
- The multi-range proof is implemented as described in Section 4.3.
- Non-interactivity is implemented as described in Section 4.4 with SHA256.

WARNING: This is research quality code.