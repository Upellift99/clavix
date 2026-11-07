Throwaway keys generated for the test suite only (ssh-keygen, no passphrase). They protect nothing; do not reuse them.

- ecdsa-p256 / ecdsa-p384 / ecdsa-p521: ECDSA signing on every NIST curve.
- dsa: the editor's algorithm gate (DSA stays unsupported). Kept as a file because recent ssh-keygen builds can no longer generate DSA keys.
