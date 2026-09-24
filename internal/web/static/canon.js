/*
 * Ledger canonical JSON + record hash, independently re-implemented for the browser so an
 * auditor does not have to trust the server's "verified" badge.
 *
 *   canonical JSON = object keys sorted (by UTF-8 bytes), no insignificant whitespace,
 *                    no HTML escaping, number literals kept exactly as written
 *   hash           = sha256hex(prev_hash + "\n" + canonical(record without hash/prev_hash))
 *
 * It must match internal/canon (Go encoding/json with SetEscapeHTML(false) over values
 * decoded with UseNumber). JSON.parse cannot be used: it loses number literals (1.0, 1e2,
 * big integers), so this file has its own small parser. A golden test runs it under node
 * against Go's output.
 */
(function (root) {
  "use strict";

  function Num(lit) { this.lit = lit; }
  function Obj() { this.map = new Map(); }
  Obj.prototype.get = function (k) { return this.map.get(k); };
  Obj.prototype.has = function (k) { return this.map.has(k); };
  Obj.prototype.keys = function () { return Array.from(this.map.keys()); };

  var NUM_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
  var HEX4 = /^[0-9a-fA-F]{4}$/;

  // Go decodes a lone UTF-16 surrogate escape ("\ud800") to U+FFFD.
  function fixSurrogates(s) {
    var out = "", changed = false;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        var d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
        if (d >= 0xdc00 && d <= 0xdfff) { out += s[i] + s[i + 1]; i++; continue; }
        out += "�"; changed = true; continue;
      }
      if (c >= 0xdc00 && c <= 0xdfff) { out += "�"; changed = true; continue; }
      out += s[i];
    }
    return changed ? out : s;
  }

  /** parse JSON text into a literal-preserving tree (Obj, Array, string, Num, true/false/null). */
  function parse(text) {
    var i = 0, n = text.length;
    function fail(m) { throw new SyntaxError("JSON: " + m + " at offset " + i); }
    function ws() {
      while (i < n) {
        var c = text.charCodeAt(i);
        if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++; else break;
      }
    }
    function str() {
      i++; // opening quote
      var out = "", start = i;
      for (;;) {
        if (i >= n) fail("unterminated string");
        var c = text.charCodeAt(i);
        if (c === 0x22) { out += text.slice(start, i); i++; return fixSurrogates(out); }
        if (c < 0x20) fail("control character in string");
        if (c !== 0x5c) { i++; continue; }
        out += text.slice(start, i);
        var e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            var h = text.substr(i, 4);
            if (!HEX4.test(h)) fail("bad \\u escape");
            out += String.fromCharCode(parseInt(h, 16));
            i += 4;
            break;
          }
          default: fail("bad escape");
        }
        start = i;
      }
    }
    function value(depth) {
      if (depth >= 10000) fail("nesting too deep"); // Go: at most 10000 nested arrays/objects
      ws();
      var c = text[i];
      if (c === "{") {
        i++;
        var o = new Obj();
        ws();
        if (text[i] === "}") { i++; return o; }
        for (;;) {
          ws();
          if (text[i] !== '"') fail("expected object key");
          var k = str();
          ws();
          if (text[i] !== ":") fail("expected ':'");
          i++;
          o.map.set(k, value(depth + 1)); // duplicate keys: last wins, as in Go
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "}") { i++; return o; }
          fail("expected ',' or '}'");
        }
      }
      if (c === "[") {
        i++;
        var a = [];
        ws();
        if (text[i] === "]") { i++; return a; }
        for (;;) {
          a.push(value(depth + 1));
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "]") { i++; return a; }
          fail("expected ',' or ']'");
        }
      }
      if (c === '"') return str();
      if (text.startsWith("true", i)) { i += 4; return true; }
      if (text.startsWith("false", i)) { i += 5; return false; }
      if (text.startsWith("null", i)) { i += 4; return null; }
      NUM_RE.lastIndex = i;
      var m = NUM_RE.exec(text);
      if (!m || m[0] === "" || m[0] === "-") fail("unexpected character");
      i = NUM_RE.lastIndex;
      return new Num(m[0]);
    }
    var v = value(0);
    ws();
    if (i !== n) fail("trailing data");
    return v;
  }

  var utf8 = new TextEncoder();

  // Go sorts map keys by their UTF-8 bytes (= code point order, not UTF-16 order).
  function cmpKeys(a, b) {
    if (a === b) return 0;
    var x = utf8.encode(a), y = utf8.encode(b), l = Math.min(x.length, y.length);
    for (var i = 0; i < l; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
  }

  function hex2(c) { return (c < 16 ? "0" : "") + c.toString(16); }

  // encodeString mirrors Go's encoding/json appendString with escapeHTML=false.
  function encodeString(s) {
    var out = '"', start = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i), rep = null;
      if (c === 0x22) rep = '\\"';
      else if (c === 0x5c) rep = "\\\\";
      else if (c < 0x20) {
        switch (c) {
          case 0x08: rep = "\\b"; break;
          case 0x0c: rep = "\\f"; break;
          case 0x0a: rep = "\\n"; break;
          case 0x0d: rep = "\\r"; break;
          case 0x09: rep = "\\t"; break;
          default: rep = "\\u00" + hex2(c);
        }
      } else if (c === 0x2028 || c === 0x2029) rep = "\\u" + c.toString(16);
      if (rep !== null) { out += s.slice(start, i) + rep; start = i + 1; }
    }
    return out + s.slice(start) + '"';
  }

  /** canonical encodes a parsed tree. */
  function canonical(v) {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (v instanceof Num) return v.lit;
    if (typeof v === "string") return encodeString(fixSurrogates(v));
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    if (v instanceof Obj) {
      var keys = v.keys().map(fixSurrogates).sort(cmpKeys);
      var dedup = new Map();
      v.map.forEach(function (val, k) { dedup.set(fixSurrogates(k), val); });
      return "{" + keys.filter(function (k, i) { return i === 0 || keys[i - 1] !== k; })
        .map(function (k) { return encodeString(k) + ":" + canonical(dedup.get(k)); }).join(",") + "}";
    }
    if (typeof v === "number" && isFinite(v)) return String(v);
    throw new TypeError("canonical: unsupported value");
  }

  function strField(rec, k) {
    var v = rec.get(k);
    return typeof v === "string" ? v : "";
  }

  /** hashBody builds the hashed object of a record (everything except hash and prev_hash). */
  function hashBody(rec) {
    var o = new Obj();
    o.map.set("id", strField(rec, "id"));
    o.map.set("chain", strField(rec, "chain"));
    o.map.set("seq", rec.get("seq"));
    o.map.set("type", strField(rec, "type"));
    o.map.set("goal_id", strField(rec, "goal_id"));
    o.map.set("actor_chain", rec.get("actor_chain"));
    o.map.set("policy_version", strField(rec, "policy_version"));
    o.map.set("payload", rec.has("payload") ? rec.get("payload") : new Obj());
    o.map.set("created_at", strField(rec, "created_at"));
    return o;
  }

  // ---- SHA-256: WebCrypto when available (secure contexts), else a small pure-JS fallback ----
  var K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

  function sha256Fallback(bytes) {
    var l = bytes.length, bitLen = l * 8;
    var padded = new Uint8Array(((l + 9 + 63) >> 6) << 6);
    padded.set(bytes);
    padded[l] = 0x80;
    var dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var W = new Array(64);
    for (var off = 0; off < padded.length; off += 64) {
      for (var t = 0; t < 16; t++) W[t] = dv.getUint32(off + t * 4);
      for (t = 16; t < 64; t++) {
        var x = W[t - 15], y = W[t - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[t] + W[t]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H.map(function (v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }).join("");
  }

  function toHex(buf) {
    return Array.from(new Uint8Array(buf)).map(function (b) { return hex2(b); }).join("");
  }

  var subtle = (root.crypto && root.crypto.subtle) || null;

  /** sha256hex resolves to {hex, engine} where engine is "webcrypto" or "fallback". */
  function sha256hex(text) {
    var bytes = utf8.encode(text);
    if (subtle) {
      return subtle.digest("SHA-256", bytes).then(function (d) { return { hex: toHex(d), engine: "webcrypto" }; });
    }
    return Promise.resolve({ hex: sha256Fallback(bytes), engine: "fallback" });
  }

  /** recordHash recomputes a record's hash from a parsed record object. */
  function recordHash(rec) {
    var canon = canonical(hashBody(rec));
    return sha256hex(strField(rec, "prev_hash") + "\n" + canon).then(function (r) {
      return { hex: r.hex, engine: r.engine, canonical: canon };
    });
  }

  /** pretty prints a tree with 2-space indentation, keeping number literals. */
  function pretty(v, ind) {
    ind = ind || "";
    var nx = ind + "  ";
    if (Array.isArray(v)) {
      if (!v.length) return "[]";
      return "[\n" + v.map(function (x) { return nx + pretty(x, nx); }).join(",\n") + "\n" + ind + "]";
    }
    if (v instanceof Obj) {
      var ks = v.keys();
      if (!ks.length) return "{}";
      return "{\n" + ks.map(function (k) { return nx + encodeString(k) + ": " + pretty(v.get(k), nx); }).join(",\n") + "\n" + ind + "}";
    }
    return canonical(v);
  }

  /** plain converts a tree to ordinary JS values (numbers become Number; for display/logic only). */
  function plain(v) {
    if (v instanceof Num) return Number(v.lit);
    if (Array.isArray(v)) return v.map(plain);
    if (v instanceof Obj) {
      var o = Object.create(null);
      v.map.forEach(function (val, k) { o[k] = plain(val); });
      return o;
    }
    return v;
  }

  var api = { parse: parse, canonical: canonical, hashBody: hashBody, recordHash: recordHash, sha256hex: sha256hex,
    sha256Fallback: sha256Fallback, pretty: pretty, plain: plain, Num: Num, Obj: Obj, encodeString: encodeString };
  root.LedgerCanon = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : globalThis);
