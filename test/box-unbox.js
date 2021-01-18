var tape = require("tape");
var ssbkeys = require("../");

tape("box, unbox", function (t) {
  var alice = ssbkeys.generate();
  var bob = ssbkeys.generate();

  var boxed = ssbkeys.box({ okay: true }, [bob.public, alice.public]);
  if (process.env.VERBOSE_TESTS) console.log("boxed", boxed);
  var msg = ssbkeys.unbox(boxed, alice.private);
  t.deepEqual(msg, { okay: true });
  t.end();
});

tape("box, unbox imprecise", function (t) {
  var alice = ssbkeys.generate();
  var bob = ssbkeys.generate();

  var boxed = ssbkeys.box({ okay: true }, [bob, alice]);
  if (process.env.VERBOSE_TESTS) console.log("boxed", boxed);
  var msg = ssbkeys.unbox(boxed, alice);
  t.deepEqual(msg, { okay: true });
  t.end();
});

tape("return undefined for invalid content", function (t) {
  var alice = ssbkeys.generate();

  var msg = ssbkeys.unbox("this is invalid content", alice.private);
  t.equal(msg, undefined);
  t.end();
});

tape("unboxKey & unboxBody", function (t) {
  var alice = ssbkeys.generate();
  var bob = ssbkeys.generate();

  var boxed = ssbkeys.box({ okay: true }, [bob.public, alice.public]);
  var k = ssbkeys.unboxKey(boxed, alice.private);
  var msg = ssbkeys.unboxBody(boxed, k);
  var msg2 = ssbkeys.unbox(boxed, alice.private);
  t.deepEqual(msg, { okay: true });
  t.deepEqual(msg, msg2);
  t.end();
});

tape("ssbSecretKeyToPrivateBoxSecret accepts keys object", function (t) {
  var keys = ssbkeys.generate();
  var curve = ssbkeys.ssbSecretKeyToPrivateBoxSecret(keys);
  t.true(Buffer.isBuffer(curve));
  t.equals(curve.length, 32);
  t.end();
});

tape("ssbSecretKeyToPrivateBoxSecret accepts keys.private", function (t) {
  var keys = ssbkeys.generate();
  var curve = ssbkeys.ssbSecretKeyToPrivateBoxSecret(keys.private);
  t.true(Buffer.isBuffer(curve));
  t.equals(curve.length, 32);
  t.end();
});
