# SSB-Keys

supplies key loading and other cryptographic functions needed in secure-scuttlebutt apps.

```js
var ssbKeys = require("ssb-keys");

// Load or create keys in this way:
var keys = ssbKeys.loadOrCreateSync("<path-to-file>");
/* keys =>
  {
    "curve": "ed25519",
    "public": "cFVodZoKwLcmXbM6UeASdl8+7+Uo8PNOuFnlcqk7qUc=.ed25519",
    "private": "lUqlXYxjkM0/ljtGnwoM0CfP6ORA2DKZnzsQ4dJ1tKJwVWh1mgrAtyZdszpR4BJ2Xz7v5Sjw8064WeVyqTupRw==.ed25519",
    "id": "@cFVodZoKwLcmXbM6UeASdl8+7+Uo8PNOuFnlcqk7qUc=.ed25519"
  }
*/

// `.generate()` is useful for testing purposes.
var keys = ssbKeys.generate();
/* keys =>
  {
    "curve": "ed25519",
    "public": "YSa2zbx07RNKQrrFX1vS5mFN+Pbnul61hd9GGymao1o=.ed25519",
    "private": "XhEkyFWb0TkhRU5t/yDTCI6Q9gwhsJM/SpL02UUwVtZhJrbNvHTtE0pCusVfW9LmYU349ue6XrWF30YbKZqjWg==.ed25519",
    "id": "@YSa2zbx07RNKQrrFX1vS5mFN+Pbnul61hd9GGymao1o=.ed25519"
  }
*/

// hmac_key` is a shared secret between two peers used to authenticate the sent
// data and can be an empty 32-byte Buffer:
var hmac_key = Buffer.alloc(32);
// Or a random Crypto buffer:
var hmac_key = crypto.randomBytes(32);
// Or a 32-byte Buffer as base-64 string:
var hmac_key = Buffer.from("7b6m0wZtYR0TevSgeNstWZUZam3IIG2B").toString(
  "base64"
);

// The `hmac_key` is a fixed value that applies to _THIS_ signature and is used
// to authenticate the data, `k` is the sender keys
var obj = ssbKeys.signObj(k, hmac_key, { foo: "bar" });
/* obj =>
  {
    "foo": "bar",
    "signature": "H39taOYa2emULWa1YDEaoLJBrbZ2GHsuVA6VsE9A1hbtpMcWpqXmZisH+nItx8BQR6JOO58K/uohMJkCrUKABQ==.sig.ed25519"
  }
*/

// Share your `hmac_key` with the message receiver so it can verify it.
ssbKeys.verifyObj(k, hmac_key, obj); // => true
```

## api

### `keys`

in the below methods, `keys` is an object of the following form:

```js
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

### generate(curve, seed, feedFormat) => keys

generate a key, with optional `seed` (which should be a 32 byte buffer, but
can be a string of any length which is then converted to a 32 byte buffer).

`curve` defaults to `ed25519` (and no other type is currently supported)

`feedFormat` can be either `classic`, `bendybutt-v1`, `gabbygrove-v1`,
`buttwoo-v1`, or `indexed-v1`. By default it's "classic".

`keys` is an object as described in [`keys`](#keys) section. `keys.id` is an
`@` sigil ID in the case of `classic` feed format and it's an SSB URI otherwise.

### sign(keys, hmac_key?, str)

signs a string `str`, and returns the signature string.

### verify(keys, sig, hmac_key?, str)

verifies a signature `sig` of the original content `str` by the author known by `keys`.

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
