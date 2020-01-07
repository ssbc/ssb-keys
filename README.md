# SSB-Keys

supplies key loading and other cryptographic functions needed in secure-scuttlebutt apps.

```js
var ssbkeys = require('ssb-keys')

//usually, load keys like this
var keys = ssbkeys.loadOrCreateSync(filename)
/* => {
  id: String,
  public: String,
  private: String
}*/

//but for testing, .generate() is useful.
var keys = ssbkeys.generate()
/* => {
  id: String,
  public: String,
  private: String
}*/


//hmac_key is a fixed value that applies to _THIS_ signature use, see below.

var obj = ssbkeys.signObj(k, hmac_key, { foo: 'bar' })
console.log(obj) /* => {
  foo: 'bar',
  signature: ...
} */
ssbkeys.verifyObj(k, hmac_key, obj) // => true
```

## api

### `keys`

in the below methods, `keys` is an object of the following form:

``` js
{
  "curve": "ed25519",
  "public": "<base64_public_key>.ed25519",
  "private": "<base64_private_key>.ed25519",
  "id": "@<base64_public_key>.ed25519"
}
```

The format of the id feed is described in the [protocol guide - keys and identities](https://ssbc.github.io/scuttlebutt-protocol-guide/#keys-and-identities)

when stored in a file, the file also contains a comment warning the reader
about safe private key security.
Comment lines are prefixed with `#` after removing them the result is valid JSON.

### hash (data, encoding) => id
Returns the sha256 hash of a given data. If encoding is not provided then it is assumed to be _binary_.

### getTag (ssb_id) => tag
The SSB ids contain a tag at the end. This function returns it.
So if you have a string like `@gaQw6zD4pHrg8zmrqku24zTSAINhRg=.ed25519` this function would return `ed25519`.
This is useful as SSB start providing features for different encryption methods and cyphers.

### loadOrCreateSync (filename) => keys

Load a file containing the your private key. the file will also
contain a comment with a warning about keeping the file secret.

Works in the browser, or stores the keys is localStorage in the browser.
(web apps should be hosted a secure way, for example [web-bootloader](https://github.com/dominictarr/web-bootloader))
In the browser, the `filename` is used as the `localStorage` key.
(note: web workers do not support localStorage, so the browser storage localtion will likely
be changed to indexeddb in the future)

If the file does not exist it will be created. there is also
variations and parts `loadOrCreate` (async), `load`, `create`
`createSync` `loadSync`. But since you only need to load once,
using the combined function is easiest.

`keys` is an object as described in [`keys`](#keys) section.

### loadOrCreate (filename, cb)

If a sync file access method is not available, `loadOrCreate` can be called with a
callback. that callback will be called with `cb(null, keys)`. If loading
the keys errored, new keys are created.

### generate(curve, seed) => keys

generate a key, with optional seed.
curve defaults to `ed25519` (and no other type is currently supported)
seed should be a 32 byte buffer.

`keys` is an object as described in [`keys`](#keys) section.

### signObj(keys, hmac_key?, obj)

signs a javascript object, and then adds a signature property to it.

If `hmac_key` is provided, the object is hmaced before signing,
which means it cannot be verified without the correct `hmac_key`.
If each way that signatures are used in your application use a different
hmac key, it means that a signature intended for one use cannot be reused in another
(chosen protocol attack)

The fine details of the signature format are described in the [protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide/#signature)

### verifyObj(keys, hmac_key?, obj)

verify a signed object. `hmac_key` must be the same value as passed to `signObj`.


### box(content, recipients) => boxed

encrypt a message content to many recipients. msg will be JSON encoded, then encrypted
with [private-box](https://github.com/auditdrivencrypto/private-box)

`recipients` must be an array of feed ids. your own feed id should be included.

the encryption format is described in the [protocol guide - encrypting](https://ssbc.github.io/scuttlebutt-protocol-guide/#encrypting)

### unbox (boxed, keys) => content

decrypt a message encrypted with `box`. If the `boxed` successfully decrypted,
the parsed JSON is returned, if not, `undefined` is returned.

the decryption process is described in the [protocol guide - decrypting](https://ssbc.github.io/scuttlebutt-protocol-guide/#decrypting)

### unboxKey (boxed, keys) => msg_key

extract the `msg_key` used to encrypt this message, or null if it cannot be decrypted.
the `msg_key` if not null, can then be passed to `unboxBody`

### unboxBody (boxed, msg_key) => content

decrypt a message `content` with a `msg_key`. returns the plaintext message content or null if
this is not the correct `msg_key`. The purpose of `unboxBody` and `unboxKey` is so support
messages that are shared then later revealed.

### secretBox (obj, key) => boxed

symmetrically encrypt an object with `key` (a buffer)

### secretUnbox (boxed, key) => obj

symmetrically decrypt an object with `key` (a buffer)

### ssbSecretKeyToPrivateBoxSecret(keys)

Convert from the ed25519 secret key (ssb secret key type) to the curve25519 key type that is used by `private-box`.

### LICENSE

MIT









