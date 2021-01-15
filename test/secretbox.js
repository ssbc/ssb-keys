var tape = require("tape");
var ssbkeys = require("..");

tape("secretBox, secretUnbox", function (t) {
  var key = Buffer.from(
    "somewhere-over-the-rainbow-way-up-high".substring(0, 32)
  );

  var boxed = ssbkeys.secretBox({ okay: true }, key);
  if (process.env.VERBOSE_TESTS) console.log("boxed", boxed);
  var msg = ssbkeys.secretUnbox(boxed, key);
  t.deepEqual(msg, { okay: true });
  t.end();
});
