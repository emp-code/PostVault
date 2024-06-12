# PostVault

[![CodeFactor](https://www.codefactor.io/repository/github/emp-code/PostVault/badge)](https://www.codefactor.io/repository/github/emp-code/PostVault)

PostVault is an encrypted storage server designed to complement All-Ears Mail, with the same privacy goal: the server knows as little as possible about its users, and keeps what it knows as private as it can.

The server simply provides a secure API to upload/download/delete a file in a slot (0-65535). Everything else, including filenames and other metadata, is left to clients. This minimal role of the server limits the server's knowledge to the bare minimum.

Clients are expected to use client-side encryption, but upload requests must also contain a key for the server-side ChaCha20 encryption, ensuring no data is ever stored unencrypted. For downloads, clients are required to decrypt the data themselves.

The server supports up to 4096 users with 65,536 files per user, with each file up to 64 GiB.

PostVault uses the [libsodium](https://libsodium.org) cryptography library.
