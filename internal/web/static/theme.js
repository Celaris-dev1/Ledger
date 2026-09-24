/* Theme: follows the OS unless the viewer picked one (remembered per browser). Loaded
   synchronously in <head> so the page never flashes the wrong theme. */
(function () {
  "use strict";
  var KEY = "ledger-theme";
  var doc = document.documentElement;
  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function apply(t) {
    if (t === "light" || t === "dark") doc.setAttribute("data-theme", t);
    else doc.removeAttribute("data-theme");
  }
  apply(stored());
  function current() {
    var t = doc.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.addEventListener("DOMContentLoaded", function () {
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    function label() {
      var next = current() === "dark" ? "light" : "dark";
      b.setAttribute("aria-label", "Switch to " + next + " mode");
      b.title = "Switch to " + next + " mode";
    }
    label();
    b.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (e) { /* private mode: not remembered */ }
      label();
    });
  });
})();
