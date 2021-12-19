# signify(1) file format

Signify is a minimalist file-signing utility using Ed25519 for tiny
keys and signatures. Key files and signatures are plain text ASCII
files.

## File format

Key files and signatures use the same basic file format:

    untrusted comment: <up to 1024 characters>\n
    <base64>\n

The second line contains binary data in base64. Additional lines
are not accepted unless it's a embedded signature.

## Secret keys

Secret keys may be encrypted. Secret keys are <xy> bytes long and have
the following structure:

- Two bytes identifying the signature algorithm: "Ed" for Ed25519
- Two bytes identifying the KDF algorithm: "BK" for bcrypt_pbkdf
- Four bytes big-endian integer for the number of KDF rounds. If the
  number of rounds is zero, the secret key is not encrypted.
- Sixteen byte salt for the KDF.
- Eight byte checksum of the decrypted secret key itself. These are
  the first eight bytes of the SHA512 of the 64 byte secret Ed25519
  key.
- Eight byte random key identifier (keynum).
- 64 bytes for the (encrypted) Ed25519 key itself. 

### Key encryption

    keylen = 64
    enckey = bcrypt_pbkdf(password, salt, kdfrounds, keylen)
    decrypted_key = enckey ^ encrypted_key

## Public key

Public keys follow this structure:

- Two bytes identifying the signature algorithm: "Ed" for Ed25519
- Eight byte random key identifier (keynum)
- 32 byte Ed25519 public key

## Signatures

- Two bytes identifying the signature algorithm: "Ed" for Ed25519
- Eight byte random key identifier (keynum)
- 64 byte long Ed25519 signature

### Embedded signatures

Embedded signatures are exactly the same as normal signatures, except
that the contents of the message are directly concatenated to the signature:

    untrusted comment: <comment>\n
    <base64 signature>\n
    message

## References

- bcrypt_pbkdf.c: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libutil/bcrypt_pbkdf.c
- signify source: http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/signify/
