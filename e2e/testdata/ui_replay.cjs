// e2e UI smoke (driven by e2e/ui_test.go): sign in with a token, open a goal's replay, press
// play, then step through every event and report the side panel's in-browser hash check.
// usage: node ui_replay.cjs BASE TOKEN GOAL  (NODE_PATH must contain playwright; CHROME = binary)
const { chromium } = require("playwright");
const [base, token, goal] = process.argv.slice(2);

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME, args: ["--no-sandbox"] });
  const page = await (await browser.newContext({ viewport: { width: 1400, height: 900 } })).newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });

  await page.goto(base + "/login?next=/chains");
  await page.fill("#token", token);
  await page.click("form[action='/auth/token'] button");
  await page.waitForURL("**/chains", { timeout: 10000 });

  await page.goto(base + "/goals/" + encodeURIComponent(goal));
  await page.waitForFunction(() => document.querySelectorAll(".events li").length > 0, null, { timeout: 15000 });
  const n = await page.$$eval(".events li", (l) => l.length);

  // Press play from the start at 60x and sample the side panel while it plays.
  await page.click("[data-act=first]");
  await page.selectOption("[data-act=speed]", "60");
  const clock0 = await page.textContent("[data-role=clock]");
  await page.click("[data-act=play]");
  const played = [];
  const deadline = Date.now() + 20000;
  let pressed = "true";
  while (Date.now() < deadline) {
    const s = await page.evaluate(() => {
      const p = document.querySelector("[data-role=panel]");
      const pills = Array.from(p.querySelectorAll(".pill")).map((x) => x.textContent.trim());
      return { text: p.textContent, pills, pressed: document.querySelector("[data-act=play]").getAttribute("aria-pressed") };
    });
    if (s.pills.includes("match") || s.pills.includes("MISMATCH")) played.push(s.pills.includes("MISMATCH") ? "MISMATCH" : "match");
    pressed = s.pressed;
    if (pressed === "false" && played.length > 0) break;
    await page.waitForTimeout(40);
  }
  const clock1 = await page.textContent("[data-role=clock]");

  // Step through every event explicitly and wait for its hash check to finish.
  const results = [];
  for (let i = 0; i < n; i++) {
    await page.click(`.events li:nth-child(${i + 1}) button`);
    const r = await page.waitForFunction(() => {
      const p = document.querySelector("[data-role=panel]");
      const pills = Array.from(p.querySelectorAll(".pill")).map((x) => x.textContent.trim());
      const check = pills.includes("MISMATCH") ? "MISMATCH" : pills.includes("match") ? "match" : null;
      if (!check) return null;
      const dts = Array.from(p.querySelectorAll("dt"));
      const h = dts.find((d) => d.textContent.trim() === "Hash");
      return { check, hash: h ? h.nextElementSibling.textContent.trim() : "" };
    }, null, { timeout: 10000 });
    results.push(await r.jsonValue());
  }
  console.log(JSON.stringify({ events: n, clock0, clock1, playedSamples: played, playStoppedAtEnd: pressed === "false", results, errors }));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
