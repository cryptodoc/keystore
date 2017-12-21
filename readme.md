# Keystore

---

> **Warning**. Work in progress.

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
3. User get encrypted key from locaStorage and decrypt it.
4. User can use secret key.

### Usage

Run server:

```shell
keystore -timeout 30s -lifetime 15m localhost:9090
```

### API

#### Create key

To put key use POST request to the `/` with json body:

```shell
curl --request POST \
  --url http://localhost:8080/ \
  --header 'content-type: application/json' \
  --data '{
	"code": 12345,
	"password": "...128 bit password..."
}'
```

Response:

```json
{
	"id": "61fb4141-c72b-48cb-a77e-db753976be29",
	"created": 1513895779,
	"expire": 1513896679,
	"password": "...128 bit password...",
	"secret": "ff9fe3ebf74c4c00d7c03c44bc78fdc5f72138d721826b804b478e7b4f41ab5e"
}
```

#### Get key

To get key use GET request to `/:id` (where :id is `id` from create request)
with token signed with `secret`.

Request:

```shell
curl --request POST \
  --url http://localhost:8080/61fb4141-c72b-48cb-a77e-db753976be29 \
  --header 'Authorization: Bearer ee7a45d32d0418f4d4a2624718bd4e88a3969cbd192918608ab1fa91808d8528.1a8519af89177551bb51edf15e2885ff6b843e21bb36abd65fbfd0b07cfe2755'
```

Response:

```json
{
	"id": "61fb4141-c72b-48cb-a77e-db753976be29",
	"created": 1513895779,
	"expire": 1513896679,
	"password": "A",
	"secret": "ff9fe3ebf74c4c00d7c03c44bc78fdc5f72138d721826b804b478e7b4f41ab5e"
}
```

#### Bearer creation

Bearer creation algorithm looks like TOTP. This is JS implementation:

```javascript
const code = 12345; // Code to unlock temporary key
const secret = '...secret...'; // Server's assigned secret to sign requests

// Get current time in seconds
const now = Math.floor(Date.now() / 1000);
// Generate token value from code and normalized time
const token = sha256(code + String(now - now % 15 ));
// Create secret sign with server's secret
const sign = sha256(token + secret);

// Concatenate token and signature with a dot
const bearer = token + '.' + sign;
```

*NOTE!* sha256 is an example function which generates correct SHA-256 hash.

### License

MIT

### Copyright

2017, CryptoDoc.
