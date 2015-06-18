
var sodium = require('libsodium-wrappers')
var crypto = require('crypto')

var B = Buffer

function Ui8 (b) {
  return new Uint8Array(b)
}

module.exports = {

  curves: ['ed25519'],

  generate: function () {
    var keys = sodium.crypto_sign_keypair()
    return {
      curve: 'ed25519',
      public: B(keys.publicKey),

      //so that this works with either sodium
      //or libsodium-wrappers (in browser)
      private: B(keys.privateKey || keys.secretKey)
    }
  },

  sign: function (private, message) {
    return B(sodium.crypto_sign_detached(Ui8(message), Ui8(private)))
  },

  verify: function (public, sig, message) {
    return sodium.crypto_sign_verify_detached(Ui8(sig), Ui8(message), Ui8(public))
  }

}
