var tape = require("tape");
var ssbkeys = require("../");
var crypto = require("crypto");
var path = "/tmp/ssb-keys_" + Date.now();

tape("create and load async", function (t) {
  if (process.env.VERBOSE_TESTS) console.log(ssbkeys);
  ssbkeys.create(path, function (err, k1) {
    if (err) throw err;
    ssbkeys.load(path, function (err, k2) {
      if (err) throw err;
      if (process.env.VERBOSE_TESTS) console.log(k1, k2);
      t.equal(k1.id.toString("hex"), k2.id.toString("hex"));
      t.equal(k1.private.toString("hex"), k2.private.toString("hex"));
      t.equal(k1.public.toString("hex"), k2.public.toString("hex"));
      t.end();
    });
  });
});

tape("create and load sync", function (t) {
  var k1 = ssbkeys.createSync(path + "1");
  var k2 = ssbkeys.loadSync(path + "1");
  t.equal(k1.id.toString("hex"), k2.id.toString("hex"));
  t.equal(k1.private.toString("hex"), k2.private.toString("hex"));
  t.equal(k1.public.toString("hex"), k2.public.toString("hex"));
  t.end();
});

tape("sign and verify a string, no hmac key", function (t) {
  var str = "secure scuttlebutt";
  var keys = ssbkeys.generate();
  var sig = ssbkeys.sign(keys.private, str);
  if (process.env.VERBOSE_TESTS) console.log(sig);
  t.ok(sig);
  t.ok(ssbkeys.verify(keys, sig, str));
  t.ok(ssbkeys.verify({ public: keys.public }, sig, str));
  t.end();
});

tape("sign and verify a hmaced string", function (t) {
  var str = "secure scuttlebutt";
  var keys = ssbkeys.generate();
  var hmac_key = crypto.randomBytes(32);
  var hmac_key2 = crypto.randomBytes(32);

  var sig = ssbkeys.sign(keys.private, hmac_key, str);
  if (process.env.VERBOSE_TESTS) console.log(sig);
  t.ok(sig);
  t.ok(ssbkeys.verify(keys, sig, hmac_key, str));
  t.ok(ssbkeys.verify({ public: keys.public }, sig, hmac_key, str));
  //a different hmac_key fails to verify
  t.notOk(ssbkeys.verify(keys, sig, hmac_key2, str));
  t.notOk(ssbkeys.verify({ public: keys.public }, sig, hmac_key2, str));

  t.end();
});

tape("sign and verify a javascript object, no hmac key", function (t) {
  var obj = require("../package.json");

  if (process.env.VERBOSE_TESTS) console.log(obj);

  var keys = ssbkeys.generate();
  var sig = ssbkeys.signObj(keys.private, obj);
  if (process.env.VERBOSE_TESTS) console.log(sig);
  t.ok(sig);
  t.ok(ssbkeys.verifyObj(keys, sig));
  t.ok(ssbkeys.verifyObj({ public: keys.public }, sig));
  t.end();
});

tape("sign and verify a javascript object, falsy hmac key", function (t) {
  var obj = require("../package.json");
  var keys = ssbkeys.generate();

  var sig1 = ssbkeys.signObj(keys.private, null, obj);
  t.ok(ssbkeys.verifyObj(keys, null, sig1), "null hmac_key");

  var sig2 = ssbkeys.signObj(keys.private, undefined, obj);
  t.ok(ssbkeys.verifyObj(keys, undefined, sig2), "undefined hmac_key");

  var sig3 = ssbkeys.signObj(keys.private, "", obj);
  t.ok(ssbkeys.verifyObj(keys, "", sig3), "empty string hmac_key");

  var sig4 = ssbkeys.signObj(keys.private, 0, obj);
  t.ok(ssbkeys.verifyObj(keys, 0, sig4), "zero hmac_key");

  var sig5 = ssbkeys.signObj(keys.private, NaN, obj);
  t.ok(ssbkeys.verifyObj(keys, NaN, sig5), "NaN hmac_key");

  t.end();
});

//allow sign and verify to also take a separate key
//so that we can create signatures that cannot be used in other places.
//(i.e. testnet) avoiding chosen protocol attacks.
tape("sign and verify a hmaced object javascript object", function (t) {
  var obj = require("../package.json");
  var hmac_key = crypto.randomBytes(32);
  var hmac_key2 = crypto.randomBytes(32);

  var keys = ssbkeys.generate();
  var sig = ssbkeys.signObj(keys.private, hmac_key, obj);
  if (process.env.VERBOSE_TESTS) console.log(sig);
  t.ok(sig);
  //verify must be passed the key to correctly verify
  t.notOk(ssbkeys.verifyObj(keys, sig));
  t.notOk(ssbkeys.verifyObj({ public: keys.public }, sig));
  t.ok(ssbkeys.verifyObj(keys, hmac_key, sig));
  t.ok(ssbkeys.verifyObj({ public: keys.public }, hmac_key, sig));
  //a different hmac_key fails to verify
  t.notOk(ssbkeys.verifyObj(keys, hmac_key2, sig));
  t.notOk(ssbkeys.verifyObj({ public: keys.public }, hmac_key2, sig));

  //assert that hmac_key may also be passed as base64

  hmac_key = hmac_key.toString("base64");
  hmac_key2 = hmac_key2.toString("base64");

  keys = ssbkeys.generate();
  sig = ssbkeys.signObj(keys.private, hmac_key, obj);
  if (process.env.VERBOSE_TESTS) console.log(sig);
  t.ok(sig);
  //verify must be passed the key to correctly verify
  t.notOk(ssbkeys.verifyObj(keys, sig));
  t.notOk(ssbkeys.verifyObj({ public: keys.public }, sig));
  t.ok(ssbkeys.verifyObj(keys, hmac_key, sig));
  t.ok(ssbkeys.verifyObj({ public: keys.public }, hmac_key, sig));
  //a different hmac_key fails to verify
  t.notOk(ssbkeys.verifyObj(keys, hmac_key2, sig));
  t.notOk(ssbkeys.verifyObj({ public: keys.public }, hmac_key2, sig));

  t.end();
});

tape("seeded keys, ed25519", function (t) {
  var seed = crypto.randomBytes(32);
  var k1 = ssbkeys.generate("ed25519", seed);
  var k2 = ssbkeys.generate("ed25519", seed);

  t.deepEqual(k1, k2);

  t.end();
});

tape('ed25519 id === "@" ++ pubkey', function (t) {
  var keys = ssbkeys.generate("ed25519");
  t.equal(keys.id, "@" + keys.public);

  t.end();
});

tape("getTag", function (t) {
  var hash = "lFluepOmDxEUcZWlLfz0rHU61xLQYxknAEd6z4un8P8=.sha256";
  var author = "@/02iw6SFEPIHl8nMkYSwcCgRWxiG6VP547Wcp1NW8Bo=.ed25519";
  t.equal(ssbkeys.getTag(hash), "sha256");
  t.equal(ssbkeys.getTag(author), "ed25519");
  t.end();
});
