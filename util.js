"use strict";
var cl = require("chloride");
var SSBURI = require("ssb-uri2");

exports.hash = function (data, enc) {
  data =
    "string" === typeof data && enc == null
      ? Buffer.from(data, "binary")
      : Buffer.from(data, enc);
  return cl.crypto_hash_sha256(data).toString("base64") + ".sha256";
};

exports.hasSigil = function hasSigil(s) {
  return /^(@|%|&)/.test(s);
};

function tag(key, tag) {
  if (!tag) throw new Error("no tag for:" + key.toString("base64"));
  return key.toString("base64") + "." + tag.replace(/^\./, "");
}

exports.keysToJSON = function keysToJSON(keys, curve, feedFormat) {
  curve = keys.curve || curve;
  feedFormat = feedFormat || "classic";

  var pub = tag(keys.public, curve);
  let id = "@" + pub;
  if (
    feedFormat === "bendybutt-v1" ||
    feedFormat === "buttwoo-v1" ||
    feedFormat === "gabbygrove-v1"
  ) {
    const classicUri = SSBURI.fromFeedSigil(id);
    const { type, data } = SSBURI.decompose(classicUri);
    id = SSBURI.compose({ type, format: feedFormat, data });
  }

  return {
    curve: curve,
    public: pub,
    private: keys.private ? tag(keys.private, curve) : undefined,
    id,
  };
};

exports.getTag = function getTag(string) {
  var i = string.indexOf(".");
  return string.substring(i + 1);
};

exports.toBuffer = function (buf) {
  if (buf == null) return buf;
  if (Buffer.isBuffer(buf)) return buf;
  var i = buf.indexOf(".");
  var start = exports.hasSigil(buf) ? 1 : 0;
  return Buffer.from(buf.substring(start, ~i ? i : buf.length), "base64");
};
