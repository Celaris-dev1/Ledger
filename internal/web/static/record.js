/* Record permalink: re-verify the record's hash in the browser (WebCrypto SHA-256 over the
   canonical form) and its link to the previous record. Values are only ever set via textContent. */
(function () {
  "use strict";
  var box = document.getElementById("browser-check");
  if (!box || !window.LedgerCanon) return;
  var C = window.LedgerCanon;
  var hashOut = box.querySelector('[data-role="hash-result"]');
  var linkOut = box.querySelector('[data-role="link-result"]');

  function pill(cls, text) {
    var s = document.createElement("span");
    s.className = "pill " + cls;
    s.textContent = text;
    return s;
  }
  function say(el, cls, badge, text) {
    el.textContent = "";
    el.appendChild(pill(cls, badge));
    el.appendChild(document.createTextNode(" " + text));
  }
  function decode(b64) {
    var bin = atob(b64), bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  }

  var rec;
  try {
    rec = C.parse(decode(box.getAttribute("data-record") || ""));
  } catch (e) {
    say(hashOut, "bad", "error", "could not parse the record: " + e.message);
    return;
  }
  var stored = rec.get("hash");
  C.recordHash(rec).then(function (r) {
    var how = r.engine === "webcrypto" ? "WebCrypto SHA-256" : "built-in SHA-256 (WebCrypto unavailable on insecure origins)";
    if (r.hex === stored) say(hashOut, "ok", "match", "hash recomputed from the canonical form with " + how + ".");
    else say(hashOut, "bad", "MISMATCH", "recomputed " + r.hex + " but the record says " + stored + ".");
    var d = document.createElement("details");
    var s = document.createElement("summary");
    s.textContent = "Canonical form that was hashed";
    var pre = document.createElement("pre");
    pre.className = "payload small";
    pre.tabIndex = 0;
    pre.textContent = (rec.get("prev_hash") || "") + "\n" + r.canonical;
    d.appendChild(s);
    d.appendChild(pre);
    box.appendChild(d);
  }, function (e) {
    say(hashOut, "bad", "error", "hashing failed: " + e);
  });

  var prev = rec.get("prev_hash") || "";
  if (box.getAttribute("data-has-prev") === "true") {
    var want = box.getAttribute("data-prev") || "";
    if (want === prev) say(linkOut, "ok", "linked", "prev_hash equals the stored hash of the previous record.");
    else say(linkOut, "bad", "broken link", "prev_hash does not equal the previous record's hash.");
  } else if (prev === "") {
    say(linkOut, "ok", "genesis", "first record of the chain (empty prev_hash).");
  } else {
    say(linkOut, "warn", "unchecked", "previous record not available.");
  }
})();
