# SSB-Keys

A common module for secure-scuttlebutt projects, provides an API to create or load elliptic-curve keypairs and to execute related crypto operations.

```js
var ssbkeys = require('ssb-keys')

ssbkeys.create(path, function(err, k) {
  console.log(k) /* => {
    id: String,
    public: String,
    private: String
  }*/
})

ssbkeys.load(path, function(err, k) {
  console.log(k) /* => {
    id: String,
    public: String,
    private: String
  }*/
})

var k = ssbkeys.createSync(path)
console.log(k) /* => {
  id: String,
  public: String,
  private: String
}*/

var k = ssbkeys.loadSync(path)
console.log(k) /* => {
  id: String,
  public: String,
  private: String
}*/

var k = ssbkeys.generate()
console.log(k) /* => {
  id: String,
  public: String,
  private: String
}*/

var hash = ssbkeys.hash(new Buffer('deadbeef', 'hex'))
var sig = ssbkeys.sign(k, hash)
ssbkeys.verify(k.public, sig, hash) // => true

var obj = ssbkeys.signObj(k, { foo: 'bar' })
console.log(obj) /* => {
  foo: 'bar',
  signature: ...
} */
ssbkeys.verifyObj(k, obj) // => true
```
