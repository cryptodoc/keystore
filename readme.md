# Keystore

---

> **Attention**. Work in progress.

---

This is useful when you need to protect data in localStorage with strong
password. You create super secret key and lightweight code (like PIN code).
You don't store code anywhere, user should remember it. Then you encrypt user
data secret with temporary secret and put it into KeyStore.

Thus we have:

```
Browser - data encrypted with secret key, secret key encrypted with temporary key
Keystore - temporary key
User - pin code to receive temporary key
```

Write algorithm:

1. User creates pin-code.
1. Create temporary 128 bit key.
2. Encrypt user secret with temporary key.
3. Put encrypted secret into localStorage.
4. Put temporary key into key store.

Read algorithm:

1. User enter pin-code and send it to the Keystore.
2. KeyStore returns temporary key.
3. User gen encrypted key from locaStorage and decrypt it.
4. User can use secret key.

### License

MIT

### Copyright

2017, CryptoDoc.
