var tape = require("tape");
var ssbkeys = require("../");
var path = require("path");
var os = require("os");
var fs = require("fs");

const keyPath = path.join(os.tmpdir(), `ssb-keys-${Date.now()}`);
if (process.env.VERBOSE_TESTS) console.log(keyPath);

tape("create and load presigil-legacy async", function (t) {
  var keys = ssbkeys.generate("ed25519");
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));

  var k2 = ssbkeys.loadSync(keyPath);
  t.equal(k2.id, "@" + keys.id);
  t.end();
});

tape("create and load presigil-legacy", function (t) {
  var keys = ssbkeys.generate("ed25519");
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));

  ssbkeys.load(keyPath, function (err, k2) {
    if (err) throw err;
    t.equal(k2.id, "@" + keys.id);
    t.end();
  });
});

tape("prevent clobbering existing keys", function (t) {
  fs.writeFileSync(keyPath, "this file intentionally left blank", "utf8");
  t.throws(function () {
    ssbkeys.createSync(keyPath);
  });
  ssbkeys.create(keyPath, function (err) {
    t.ok(err);
    fs.unlinkSync(keyPath);
    t.end();
  });
});

tape("loadOrCreate can load", function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-1-${Date.now()}`);
  var keys = ssbkeys.generate("ed25519");
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));

  ssbkeys.loadOrCreate(keyPath, (err, k2) => {
    t.error(err);
    t.equal(k2.id, "@" + keys.id);
    t.end();
  });
});

tape("loadOrCreate can create", function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-2-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);

  ssbkeys.loadOrCreate(keyPath, (err, keys) => {
    t.error(err);
    t.true(keys.public.length > 20, "keys.public is a long string");
    t.true(keys.private.length > 20, "keys.private is a long string");
    t.true(keys.id.length > 20, "keys.id is a long string");
    t.end();
  });
});

tape("loadOrCreate can create buttwoo-v1 keys", function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-21-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);

  ssbkeys.loadOrCreate(keyPath, { feedFormat: "buttwoo-v1" }, (err, keys) => {
    t.error(err);
    t.true(keys.id.startsWith("ssb:feed/buttwoo-v1/"));
    t.equals(keys.id.length, 64);
    t.false(keys.id.endsWith(".ed25519"));
    t.end();
  });
});

tape("loadOrCreateSync can load", function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-3-${Date.now()}`);
  var keys = ssbkeys.generate("ed25519");
  keys.id = keys.id.substring(1);
  fs.writeFileSync(keyPath, JSON.stringify(keys));

  var k2 = ssbkeys.loadOrCreateSync(keyPath);
  t.equal(k2.id, "@" + keys.id);
  t.end();
});

tape("loadOrCreateSync can create", function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-4-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);

  var keys = ssbkeys.loadOrCreateSync(keyPath);
  t.true(keys.public.length > 20, "keys.public is a long string");
  t.true(keys.private.length > 20, "keys.private is a long string");
  t.true(keys.id.length > 20, "keys.id is a long string");
  t.end();
});

tape("loadOrCreateSync can create buttwoo-v1 keys", function (t) {
  var keyPath = path.join(os.tmpdir(), `ssb-keys-41-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);

  const keys = ssbkeys.loadOrCreateSync(keyPath, { feedFormat: "buttwoo-v1" });
  t.true(keys.id.startsWith("ssb:feed/buttwoo-v1/"));
  t.equals(keys.id.length, 64);
  t.false(keys.id.endsWith(".ed25519"));
  t.end();
});

tape("don't create dir for fully-specified path", function (t) {
  const keyPath = path.join(os.tmpdir(), `ssb-keys-5-${Date.now()}`);
  t.equal(fs.existsSync(keyPath), false);
  ssbkeys.loadOrCreate(keyPath, (err) => {
    t.error(err);
    t.true(fs.lstatSync(keyPath).isFile());

    ssbkeys.loadOrCreate(keyPath, (err, keys) => {
      t.error(err);
      t.equal(keys.public.length, 52);
      fs.unlinkSync(keyPath);
      t.end();
    });
  });
});
