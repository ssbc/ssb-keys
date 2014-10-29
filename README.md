# SSB-Keys

A common module for secure-scuttlebutt projects, provides an API to create or load elliptic-curve keypairs.

```js
var ssbkeys = require('ssb-keys')

ssbkeys.create(path, function(err, k) {
  console.log(k) /* => {
    id: Buffer(...),
    public: Buffer(...),
    private: Buffer(...)
  }*/
})

ssbkeys.load(path, function(err, k) {
  console.log(k) /* => {
    id: Buffer(...),
    public: Buffer(...),
    private: Buffer(...)
  }*/
})

var k = ssbkeys.createSync(path)
console.log(k) /* => {
  id: Buffer(...),
  public: Buffer(...),
  private: Buffer(...)
}*/
```