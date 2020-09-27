# 8.0.0

- BREAKING CHANGE: Node.js versions lower than 5.10.0 are not supported anymore
- Internally uses `Buffer.from` instead of the deprecated constructor `new Buffer`
- Depend on `chloride@2.2.8`, not allowing `chloride@2.3.x`
