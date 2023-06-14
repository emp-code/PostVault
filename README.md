# PostVault

[![CodeFactor](https://www.codefactor.io/repository/github/emp-code/PostVault/badge)](https://www.codefactor.io/repository/github/emp-code/PostVault)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/0cf32842dee24c93b0d8cb43f57162f5)](https://www.codacy.com/gh/emp-code/PostVault/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=emp-code/PostVault&amp;utm_campaign=Badge_Grade)

PostVault is an encrypted storage server designed to complement All-Ears Mail, with the same privacy goal: the server knows as little as possible about its users, and keeps what it knows as private as it can.

The server simply provides a secure API to upload/download/delete a file in a slot (0-4095). Everything else, including filenames and other metadata, is left to clients. This minimal role of the server limits the server's knowledge to the bare minimum.

Clients are expected to use client-side encryption, but upload requests must also contain a key for the server-side AES256-CTR encryption, ensuring no data is ever stored unencrypted. For downloads, clients are required to decrypt the data themselves.

Users are identified by a binary identifier and through authenticated encryption. All client-server communication is designed to be secure and private even without HTTPS, which the server does not support for simplicity.

PostVault uses the [libsodium](https://libsodium.org) and [TinyAES](https://github.com/kokke/tiny-AES-c) cryptography libraries.
