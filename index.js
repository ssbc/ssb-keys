"use strict";
var sodium = require("chloride");
var pb = require("private-box");
var u = require("./util");
var isBuffer = Buffer.isBuffer;

//UTILS

function clone(obj) {
  var _obj = {};
  for (var k in obj) {
    if (Object.hasOwnProperty.call(obj, k)) _obj[k] = obj[k];
  }
  return _obj;
}

var hmac = sodium.crypto_auth;

exports.hash = u.hash;

exports.getTag = u.getTag;

function isObject(o) {
  return "object" === typeof o;
}

function isString(s) {
  return "string" === typeof s;
}

var curves = {};
curves.ed25519 = require("./sodium");

function getCurve(keys) {
  var curve = keys.curve;

  if (!keys.curve && isString(keys.public)) keys = keys.public;

  if (!curve && isString(keys)) curve = u.getTag(keys);

  if (!curves[curve]) {
    throw new Error(
      "unkown curve:" + curve + " expected: " + Object.keys(curves)
    );
  }

  return curve;
}

//this should return a key pair:
// {curve: curve, public: Buffer, private: Buffer}

exports.generate = function (curve, seed) {
  curve = curve || "ed25519";

  if (!curves[curve]) throw new Error("unknown curve:" + curve);

  return u.keysToJSON(curves[curve].generate(seed), curve);
};

//import functions for loading/saving keys from storage
var storage = require("./storage")(exports.generate);
for (var key in storage) exports[key] = storage[key];

exports.loadOrCreate = function (filename, cb) {
  exports.load(filename, function (err, keys) {
    if (!err) return cb(null, keys);
    exports.create(filename, cb);
  });
};

exports.loadOrCreateSync = function (filename) {
  try {
    return exports.loadSync(filename);
  } catch (err) {
    return exports.createSync(filename);
  }
};

//takes a public key and a hash and returns a signature.
//(a signature must be a node buffer)

function sign(keys, msg) {
  if (isString(msg)) msg = Buffer.from(msg);
  if (!isBuffer(msg)) throw new Error("msg should be buffer");
  var curve = getCurve(keys);

  return (
    curves[curve]
      .sign(u.toBuffer(keys.private || keys), msg)
      .toString("base64") +
    ".sig." +
    curve
  );
}

//takes a public key, signature, and a hash
//and returns true if the signature was valid.
function verify(keys, sig, msg) {
  if (isObject(sig))
    throw new Error(
      "signature should be base64 string, did you mean verifyObj(public, signed_obj)"
    );
  return curves[getCurve(keys)].verify(
    u.toBuffer(keys.public || keys),
    u.toBuffer(sig),
    isBuffer(msg) ? msg : Buffer.from(msg)
  );
}

// OTHER CRYPTO FUNCTIONS

/**
 * To guarantee backwards compatibility, this function determines the true
 * essence of each of the parameters and swaps them if necessary.
 * This function is intended to be used only with `signObj` and `verifyObj`.
 * Additional context:
 *   - https://github.com/ssb-js/ssb-keys/issues/67
 *   - https://github.com/ssb-js/ssb-keys/pull/80
 * @param {Any} obj
 * @param {Any} hmac_key
 * @return {Array} [obj, hmac_key]
 */
function validateParameters(obj, hmac_key) {
  var temp;

  if (
    (isObject(hmac_key) || !hmac_key) &&
    (isBuffer(obj) || isString(obj) || !obj)
  ) {
    console.warn(
      "\nWARNING! The parameter order (keys, hmac_key?, obj) has been deprecated," +
        " please consider using the (keys, obj, hmac_key?) order instead.\n"
    );
    // Swap the parameters content before return.
    temp = obj || null;
    obj = hmac_key;
    hmac_key = temp;
  }

  return [obj, hmac_key];
}

exports.signObj = function (keys, obj, hmac_key) {
  var params = validateParameters(obj, hmac_key);
  var _obj = clone(params[0]);
  var _hmac_key = params[1];
  var b = Buffer.from(JSON.stringify(_obj, null, 2));

  if (_hmac_key) b = hmac(b, u.toBuffer(_hmac_key));
  _obj.signature = sign(keys, b);

  return _obj;
};

exports.verifyObj = function (keys, obj, hmac_key) {
  var params = validateParameters(obj, hmac_key);
  var _obj = clone(params[0]);
  var _hmac_key = params[1];
  var sig = _obj.signature;
  delete _obj.signature;
  var b = Buffer.from(JSON.stringify(_obj, null, 2));

  if (_hmac_key) b = hmac(b, u.toBuffer(_hmac_key));

  return verify(keys, sig, b);
};

exports.box = function (msg, recipients) {
  msg = Buffer.from(JSON.stringify(msg));

  recipients = recipients.map(function (keys) {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(
      u.toBuffer(keys.public || keys)
    );
  });

  return pb.multibox(msg, recipients).toString("base64") + ".box";
};

function ssbSecretKeyToPrivateBoxSecret(keys) {
  return sodium.crypto_sign_ed25519_sk_to_curve25519(
    u.toBuffer(keys.private || keys)
  );
}

exports.ssbSecretKeyToPrivateBoxSecret = ssbSecretKeyToPrivateBoxSecret;

exports.unboxKey = function (boxed, keys) {
  boxed = u.toBuffer(boxed);
  var sk = ssbSecretKeyToPrivateBoxSecret(keys);
  return pb.multibox_open_key(boxed, sk);
};

exports.unboxBody = function (boxed, key) {
  if (!key) return null;
  boxed = u.toBuffer(boxed);
  key = u.toBuffer(key);
  var msg = pb.multibox_open_body(boxed, key);
  try {
    return JSON.parse("" + msg);
  } catch (_) {
    return;
  }
};

exports.unbox = function (boxed, keys) {
  boxed = u.toBuffer(boxed);

  var sk =
    keys._exchangeKey ||
    sodium.crypto_sign_ed25519_sk_to_curve25519(
      u.toBuffer(keys.private || keys)
    );
  if (keys.private) keys._exchangeKey = sk; //if keys is an object, cache the curve key.
  try {
    var msg = pb.multibox_open(boxed, sk);
    return JSON.parse("" + msg);
  } catch (_) {
    return;
  }
};

exports.secretBox = function secretBox(data, key) {
  if (!data) return;
  var ptxt = Buffer.from(JSON.stringify(data));
  return sodium.crypto_secretbox_easy(ptxt, key.slice(0, 24), key);
};

exports.secretUnbox = function secretUnbox(ctxt, key) {
  var ptxt = sodium.crypto_secretbox_open_easy(ctxt, key.slice(0, 24), key);
  if (!ptxt) return;
  return JSON.parse(ptxt.toString());
};
