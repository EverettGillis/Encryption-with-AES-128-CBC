# Rijndael Block Cypher

**About**
\
\
Visualize encryption with AES implementation in python. 

\
**Introduction**
\
\
The Advanced Encryption Standard (AES) established in FIPS 197 includes specific bit length variants of the Rijndael block cypher (NIST 2001). Here, a python implementation of this method uses ~1500 lines of code to accurately model what is today the standard of encryption in use by the U.S. government (Smid 2021).

\
**Algorithm Overview**
\
\
On a high level, AES-128 takes two-dimensional cyphertext and cypherkey arrays of $Nb=4$ rows of 32 bits. Cyphertext constituting the **state** matrix is combined with the cypherkey before subsequent rounds of substitution and permutation scramble the state and key expansion extends the length of the cypherkey. With some exception, each of $Nr=10$ rounds sees the same procedures performed on the state:

- SubBytes (substitution):\
Bytes of the state are mapped to values of the ```S_box```.

- ShiftRows (permutation):\
Elements in each row of the state are cycled by increasing intervals.

- MixColumns (permutation):\
The polynomial of each 32-bit **word** of the state is multiplied by an irreducible polynomial under the Galois field $GF(2^{8})$.

- AddRoundKey:\
The state is XOR'ed with the last block of the key schedule generated in key expansion.

The inverse cypher sees the above operations generally performed in reverse order, with the ```S_box``` in SubBytes and the primitive matrix in MixColumns being the inverses of those used in encryption. In cypher block chaining (CBC), blocks of data are procedurally encrypted to generate cypherkeys for subsequent block encryption, and the inverse is performed in decryption.

Detailed mathematical preliminaries and other specifications may be found in NIST (2001) and Wikipedia (2023).

\
**Operation and Intended Use**
\
\
```AES_program_manager.py``` is the interface through which both encryption and decryption files are run. Save all three files to the same folder. Required: Python 3.10, numpy 1.22.3, tkinter 0.1.0.

```algorithm_validation.pdf``` demonstrates the efficacy of the implementation in accurately and reliably encrypting and decrypting data.

This implementation is designed to illustrate the process of encryption in real time, not to perform it quickly and securely. Encryption in professional use is performed in isolation where it is time efficient and less vulnerable to timing and sidechannel attacks.

\
**Citations**
\
\
National Institute of Standards and Technology (2001) Advanced Encryption Standard (AES). J Fed Info Proc Stan Pub 197. https://doi.org/10.6028/NIST.FIPS.197.

Smid, M.E. (2021) Development of the Advanced Encryption Standard. J Res Natl Inst Stan 126:126024. https://doi.org/10.6028/jres.126.024.

Wikipedia (2023) Advanced Encryption Standard. https://en.wikipedia.org/wiki/Advanced_Encryption_Standard.
