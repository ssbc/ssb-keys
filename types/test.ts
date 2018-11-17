import * as keys from 'ssb-keys'

// $ExpectType string
keys.getTag('foo')

// $ExpectType Key
keys.generate()

// $ExpectType Key
keys.generate('ed25519')

// $ExpectType Key
keys.generate('ed25519', new Buffer('test'))

// $ExpectError
keys.generate(23)

// $ExpectType void
keys.load('foo.ed25519', (error, key) => {})

// $ExpectError
keys.load(23, (error, key) => {})

// $ExpectType Key
keys.loadSync('foo.ed25519')

// $ExpectError
keys.loadSync(23)

// $ExpectType void
keys.create('foo.ed25519', (error, key) => {})

// $ExpectType void
keys.create('foo.ed25519', 'ed25519', (error, key) => {})

// $ExpectType void
keys.create('foo.ed25519', 'ed25519', true, (error, key) => {})

// $ExpectError
keys.create(23, (error, key) => {})

// $ExpectType Key
keys.createSync('foo.ed25519')

// $ExpectType Key
keys.createSync('foo.ed25519', 'ed25519', true)

// $ExpectType void
keys.loadOrCreate('foo.ed25519', (error, key) => {})

// $ExpectType Key
keys.loadOrCreateSync('foo.ed25519')

const key: keys.Key = {
  curve: 'ed25519',
  public: '',
  private: '',
  id: ''
}

const hmac_key = new Buffer('');

// $ExpectType SignedObject
keys.signObj(key, {});

// $ExpectType SignedObject
keys.signObj(key, hmac_key, {});

// $ExpectType boolean
keys.verifyObj(key, {})

// $ExpectType boolean
keys.verifyObj(key, hmac_key, {})

// $ExpectType string
keys.box('', [key])

// $ExpectType any
keys.unbox('', key)
