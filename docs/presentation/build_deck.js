// Final presentation deck for the 14-795 project, built from results/final via /tmp/deck_data.json.
const pptxgen = require("pptxgenjs");
require("child_process").execFileSync("python3", ["/home/claude/deck/rq2_chart.py", "/home/claude/deck/deck_data.json"], { cwd: "/home/claude/deck" });
const { applyTheme } = require("/root/.claude/skills/synced/d48f7fe3-4631-4681-bb7f-c7722f7456e0_5d4a33f1-1db8-4324-98a7-12fc1282939a/pptx/scripts/apply_theme.js");
const D = require("./deck_data.json");

const THEME = {
  name: "Interproc Vuln Pairs",
  headFontFace: "Arial",
  bodyFontFace: "Arial",
  colors: {
    dk1: "111111", lt1: "FFFFFF", dk2: "1F4E9E", lt2: "E7EEF8",
    accent1: "2A78D6", accent2: "EB6834", accent3: "1BAF7A", accent4: "A8A7A0",
    accent5: "C5D5EA", accent6: "52514E", hlink: "1F4E9E", folHlink: "6250D6",
  },
};
const HEX = { blue: "2A78D6", orange: "EB6834", aqua: "1BAF7A", grey: "A8A7A0", navy: "1F4E9E", ink2: "52514E", grid: "E4E3DF", card: "E7EEF8", cardLine: "C5D5EA", warm: "FDF1E7", warmLine: "F2C9A8" };

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9"; // 10 x 5.625 in
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
pres.title = "Do LLMs Really Find Interprocedural Vulnerabilities? Final presentation";
pres.author = "Justun Gao, Siwei Tan, Mengchao Ren";
const C = pres.SchemeColor;

const pct = (v, d = 0) => `${(100 * v).toFixed(d)}%`;
const SCRIPT = require("./script.json");
const NOTE = (k) => { let el = 0; for (let i = 0; i < k; i++) { const [m, x] = SCRIPT[i].t.split(":"); el += +m * 60 + +x; } const [m, x] = SCRIPT[k].t.split(":"); const end = el + (+m * 60 + +x); const f = (v) => `${Math.floor(v / 60)}:${String(v % 60).padStart(2, "0")}`; return `[${SCRIPT[k].t}  ·  ${f(el)}–${f(end)}]\n\n${SCRIPT[k].s}`; };
const R = (m, c = "CO") => D.rq1[`${m}|${c}`];
const MODELS = ["Claude Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini", "GPT-4.1 Mini"];
const bestMcc = MODELS.flatMap((m) => ["CO", "CC", "CK"].map((c) => ({ m, c, v: R(m, c).MCC }))).reduce((a, b) => (b.v > a.v ? b : a));

// ---------------------------------------------------------------- layouts
pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: "FFFFFF" },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.5, y: 0.28, w: 9.0, h: 0.62, fontSize: 26, bold: true, color: C.text1, valign: "top", align: "left", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "lead", type: "body", x: 0.5, y: 0.92, w: 9.0, h: 0.42, fontSize: 13, bold: true, color: C.text1, valign: "top", align: "left", margin: 0 }, text: "" } },
  ],
  slideNumber: { x: 9.2, y: 5.22, w: 0.4, h: 0.25, fontSize: 10, color: HEX.ink2, align: "right" },
});
pres.defineSlideMaster({ title: "TITLE", background: { color: "FFFFFF" }, objects: [] });

function title(slide, black, blue) {
  slide.addText([
    { text: black, options: { color: C.text1 } },
    { text: blue, options: { color: C.text2 } },
  ], { placeholder: "title" });
}

// pptxgenjs writes chart categories as a one-level multiLvlStrRef. PowerPoint reads it, but Keynote and
// Google Slides fall back to 1, 2, 3. Rewrite them as a plain strRef so every viewer shows the labels.
async function plainCategoryLabels(file) {
  const JSZip = require(require.resolve("jszip", { paths: [require.resolve("pptxgenjs")] }));
  const fs = require("fs");
  const zip = await JSZip.loadAsync(fs.readFileSync(file));
  for (const name of Object.keys(zip.files).filter((n) => /^ppt\/charts\/chart\d+\.xml$/.test(n))) {
    let xml = await zip.file(name).async("string");
    xml = xml.replace(/<c:multiLvlStrRef>\s*(<c:f>[^<]*<\/c:f>)\s*<c:multiLvlStrCache>\s*(<c:ptCount val="\d+"\/>)\s*<c:lvl>([\s\S]*?)<\/c:lvl>\s*<\/c:multiLvlStrCache>\s*<\/c:multiLvlStrRef>/g,
      (_, f, count, pts) => `<c:strRef>${f}<c:strCache>${count}${pts}</c:strCache></c:strRef>`);
    zip.file(name, xml);
  }
  fs.writeFileSync(file, await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }));
}
function lead(slide, text) { slide.addText(text, { placeholder: "lead" }); }
function source(slide, text) {
  slide.addText(text, { x: 0.5, y: 5.2, w: 8.5, h: 0.28, fontSize: 9, italic: true, color: HEX.ink2, isTextBox: true, margin: 0, objectName: "source" });
}
function card(slide, x, y, w, h, opts = {}) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: opts.fill || HEX.card }, line: { color: opts.line || HEX.cardLine, width: 1 }, objectName: opts.name || "card" });
}
function cardText(slide, x, y, w, h, runs, opts = {}) {
  slide.addText(runs, { x: x + 0.15, y: y + 0.1, w: w - 0.3, h: h - 0.2, fontSize: opts.fontSize || 12, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 3, objectName: opts.name || "card text" });
}
const axisFont = { catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt", dataLabelFontFace: "+mn-lt", legendFontFace: "+mn-lt", titleFontFace: "+mn-lt" };
const quietAxes = {
  catAxisLabelColor: "111111", valAxisLabelColor: HEX.ink2, catAxisLabelFontSize: 11, valAxisLabelFontSize: 10,
  valGridLine: { color: HEX.grid, size: 0.75 }, catGridLine: { style: "none" }, catAxisLineShow: false, valAxisLineShow: false,
  dataLabelColor: "111111", dataLabelFontSize: 10, ...axisFont,
};

// ---------------------------------------------------------------- 1. title
pres.addSection({ title: "Title" });
{
  const s = pres.addSlide({ masterName: "TITLE", sectionTitle: "Title" });
  s.addText("14-795 Final Presentation", { x: 0.5, y: 0.85, w: 5.2, h: 0.35, fontSize: 13, bold: true, color: HEX.ink2, isTextBox: true, margin: 0 });
  s.addText([
    { text: "Do LLMs Really Find ", options: { color: C.text1, breakLine: true } },
    { text: "Interprocedural Vulnerabilities?", options: { color: C.text2 } },
  ], { x: 0.5, y: 1.25, w: 5.2, h: 1.6, fontSize: 32, bold: true, isTextBox: true, margin: 0, valign: "top", objectName: "deck title" });
  s.addText("What happens to an LLM vulnerability-detection benchmark when every CVE is also shown in its fixed form", { x: 0.5, y: 2.95, w: 5.0, h: 0.75, fontSize: 14, color: C.text1, isTextBox: true, margin: 0, valign: "top" });
  s.addText("Justun Gao · Siwei Tan · Mengchao Ren", { x: 0.5, y: 3.95, w: 5.2, h: 0.35, fontSize: 15, bold: true, color: C.text2, isTextBox: true, margin: 0 });

  const stats = [
    [pct(R("Gemini 3 Flash").fpr, 0), "of patched functions still flagged by Gemini 3 Flash (Haiku 4.5: " + pct(R("Claude Haiku 4.5").fpr, 0) + ")", HEX.card, HEX.cardLine],
    ["≈ 0.5", "precision for every model once fixed code is included (paper: 1.0 by construction)", "F2F2F2", "D9D9D9"],
    ["1 of 3", "models tested pair by pair whose false alarms drop with interprocedural context (GPT-5 Mini)", "E8F5EE", "B9E0CB"],
  ];
  stats.forEach(([big, small, fill, line], i) => {
    const y = 0.85 + i * 1.32;
    card(s, 6.05, y, 3.45, 1.12, { fill, line, name: "stat card" });
    s.addText(big, { x: 6.25, y: y + 0.12, w: 1.25, h: 0.85, fontSize: 28, bold: true, color: C.text2, isTextBox: true, margin: 0, valign: "middle" });
    s.addText(small, { x: 7.5, y: y + 0.12, w: 1.88, h: 0.88, fontSize: 10.5, color: C.text1, isTextBox: true, margin: 0, valign: "middle" });
  });
  s.addText("C subset of ReposVul · 343 CVEs · 4 models × 3 context levels · all numbers from saved model outputs", { x: 0.5, y: 4.95, w: 9.0, h: 0.3, fontSize: 10, italic: true, color: HEX.ink2, isTextBox: true, margin: 0 });
  s.addNotes(NOTE(0));
}

// ---------------------------------------------------------------- 2. goals: problem
pres.addSection({ title: "Goals" });
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Goals" });
  title(s, "Goals: ", "Scores Without False Positives");
  lead(s, "The prior study judges detectors on vulnerable code only, so false alarms were never measured");
  // left text
  s.addText([
    { text: "Why it matters. ", options: { bold: true } },
    { text: "In code review or SAST triage most functions are safe; a detector that flags everything buries the real bugs.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true, fontSize: 6 } },
    { text: "The baseline (Lira et al. 2026). ", options: { bold: true } },
    { text: "451 CVEs, every sample vulnerable. Precision is 1 by construction, so F1 = 2R / (1 + R): Claude Haiku 4.5 reports F1 0.988 with recall 0.976.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true, fontSize: 6 } },
    { text: "The authors flag it themselves: ", options: { bold: true } },
    { text: "“The absence of negative examples … prevents the evaluation of false positive rates.” (Sec. 6)" },
  ], { x: 0.5, y: 1.55, w: 5.2, h: 2.7, fontSize: 13, color: C.text1, valign: "top", isTextBox: true, margin: 0 });
  // confusion matrix
  const x0 = 6.55, y0 = 1.95, cw = 1.3, ch = 0.85;
  s.addText("What the baseline can measure", { x: 5.95, y: 1.45, w: 3.6, h: 0.3, fontSize: 11, bold: true, color: HEX.ink2, align: "center", isTextBox: true, margin: 0 });
  s.addText("truly vulnerable", { x: x0, y: 1.72, w: cw, h: 0.22, fontSize: 9.5, color: HEX.ink2, align: "center", isTextBox: true, margin: 0 });
  s.addText("truly safe", { x: x0 + cw + 0.1, y: 1.72, w: cw, h: 0.22, fontSize: 9.5, color: HEX.ink2, align: "center", isTextBox: true, margin: 0 });
  [["TP", 0, 0, true], ["FP", 1, 0, false], ["FN", 0, 1, true], ["TN", 1, 1, false]].forEach(([t, cx, cy, on]) => {
    const x = x0 + cx * (cw + 0.1), y = y0 + cy * (ch + 0.1);
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: cw, h: ch, rectRadius: 0.06, fill: { color: on ? HEX.card : "F4F4F2" }, line: { color: on ? HEX.cardLine : "D9D9D9", width: 1 } });
    s.addText(t, { x, y, w: cw, h: ch, fontSize: 20, bold: true, color: on ? "111111" : "B0AFA8", align: "center", valign: "middle", isTextBox: true, margin: 0 });
  });
  s.addText("said vulnerable", { x: 5.75, y: y0, w: 0.75, h: ch, fontSize: 9.5, color: HEX.ink2, align: "right", valign: "middle", isTextBox: true, margin: 0 });
  s.addText("said safe", { x: 5.75, y: y0 + ch + 0.1, w: 0.75, h: ch, fontSize: 9.5, color: HEX.ink2, align: "right", valign: "middle", isTextBox: true, margin: 0 });
  s.addShape(pres.shapes.RECTANGLE, { x: x0 + cw + 0.05, y: y0 - 0.05, w: cw + 0.1, h: 2 * ch + 0.2, fill: { type: "none" }, line: { color: "C0392B", width: 1.25, dashType: "dash" } });
  s.addText("never measured", { x: x0 + cw + 0.05, y: y0 + 2 * ch + 0.2, w: cw + 0.1, h: 0.25, fontSize: 10, bold: true, italic: true, color: "C0392B", align: "center", isTextBox: true, margin: 0 });
  // bottom example
  card(s, 0.5, 4.35, 9.0, 0.72, { name: "example card" });
  s.addText([
    { text: "Our fix: ask about the patched code too. ", options: { bold: true, color: C.text2 } },
    { text: "CVE-2011-1078 (Linux): the fix adds one line, memset(&cinfo, 0, sizeof(cinfo)). A detector that understands the bug should flag the first version and clear the second." },
  ], { x: 0.65, y: 4.42, w: 8.7, h: 0.58, fontSize: 12, color: C.text1, valign: "middle", isTextBox: true, margin: 0 });
  s.addNotes(NOTE(1));
}

// ---------------------------------------------------------------- 3. goals: RQs
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Goals" });
  title(s, "Goals: ", "Research Questions and Final Scope");
  lead(s, "Same questions as the proposal, narrowed to the C subset for enough statistical power");
  const rqs = [
    ["RQ1", "False alarms", "With the fixed version of each CVE added, what are precision, false-alarm rate (FPR), MCC and pairwise accuracy for each model × context?", "H1: precision and pair accuracy fall far below the near-perfect reported F1."],
    ["RQ2", "Does context help?", "Callers/callees barely changed recall in the paper. Do they reduce false alarms instead?", "H2: full context lowers false alarms, at least for the stronger models."],
    ["Extra", "Error analysis", "When a model flags patched code, does it point at the patch, at other code, or at a memorised CVE?", "Manual labels of sampled alerts + CVE-citation and CVE-year checks."],
  ];
  rqs.forEach(([tag, head, q, h], i) => {
    const x = 0.5 + i * 3.07;
    card(s, x, 1.55, 2.86, 2.55, { name: `${tag} card` });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + 0.15, y: 1.7, w: 0.75, h: 0.36, rectRadius: 0.05, fill: { color: HEX.navy }, line: { color: HEX.navy } });
    s.addText(tag, { x: x + 0.15, y: 1.7, w: 0.75, h: 0.36, fontSize: 12, bold: true, color: "FFFFFF", align: "center", valign: "middle", isTextBox: true, margin: 0 });
    s.addText(head, { x: x + 1.0, y: 1.7, w: 1.75, h: 0.36, fontSize: 13, bold: true, color: C.text1, valign: "middle", isTextBox: true, margin: 0 });
    s.addText(q, { x: x + 0.15, y: 2.18, w: 2.56, h: 1.2, fontSize: 11.5, color: C.text1, valign: "top", isTextBox: true, margin: 0 });
    s.addText(h, { x: x + 0.15, y: 3.38, w: 2.56, h: 0.64, fontSize: 11, italic: true, color: C.text2, valign: "top", isTextBox: true, margin: 0 });
  });
  const scope = [["343", "C CVEs with a fixed version"], ["718", "vulnerable / fixed pairs (CO 343, CC 196, CK 179)"], ["4", "models (3 new runs + GPT-4.1 Mini)"], ["5,744", "model answers analysed"]];
  scope.forEach(([n, t], i) => {
    const x = 0.5 + i * 2.3;
    s.addText(n, { x, y: 4.28, w: 0.95, h: 0.6, fontSize: 22, bold: true, color: C.text2, valign: "middle", isTextBox: true, margin: 0 });
    s.addText(t, { x: x + 0.95, y: 4.28, w: 1.32, h: 0.6, fontSize: 10, color: HEX.ink2, valign: "middle", isTextBox: true, margin: 0 });
  });
  s.addNotes(NOTE(2));
}

// ---------------------------------------------------------------- 4. system: pipeline
pres.addSection({ title: "System" });
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "System" });
  title(s, "System: ", "Paired Evaluation Pipeline");
  lead(s, "Each CVE is asked twice per context: as vulnerable code, and with every target function fixed");
  const steps = [
    ["1  CVE records", "raw_cves JSON: vulnerable + fixed code of each function, before/after callers and callees", false],
    ["2  Pair builder", "swap each target function for its fix; deterministic duplicate-record choice; misalignment check", true],
    ["3  Prompts", "authors' prompt template, CO / CC / CK × both versions; vulnerable prompts byte-identical to theirs", false],
    ["4  LLM runs", "authors' settings; new resumable multi-provider runner with budget caps; retry once if unparsed", true],
    ["5  Analysis", "recall, precision, FPR, MCC, pair outcomes; bootstrap CIs; McNemar + Holm; false-alarm labels", true],
  ];
  const w = 1.66, gap = 0.17, y = 1.6, h = 1.95;
  steps.forEach(([head, body, isNew], i) => {
    const x = 0.5 + i * (w + gap);
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.08, fill: { color: isNew ? HEX.card : "F4F4F2" }, line: { color: isNew ? HEX.navy : "D9D9D9", width: isNew ? 1.75 : 1 }, objectName: `step ${i + 1}` });
    s.addText(head, { x: x + 0.12, y: y + 0.12, w: w - 0.24, h: 0.35, fontSize: 12.5, bold: true, color: isNew ? C.text2 : C.text1, isTextBox: true, margin: 0 });
    s.addText(body, { x: x + 0.12, y: y + 0.52, w: w - 0.24, h: h - 0.6, fontSize: 10.5, color: C.text1, valign: "top", isTextBox: true, margin: 0 });
    if (isNew) {
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + w - 0.62, y: y - 0.16, w: 0.56, h: 0.26, rectRadius: 0.04, fill: { color: HEX.navy }, line: { color: HEX.navy } });
      s.addText("NEW", { x: x + w - 0.62, y: y - 0.16, w: 0.56, h: 0.26, fontSize: 9, bold: true, color: "FFFFFF", align: "center", valign: "middle", isTextBox: true, margin: 0 });
    }
    if (i < steps.length - 1) {
      s.addShape(pres.shapes.RIGHT_ARROW, { x: x + w + 0.01, y: y + h / 2 - 0.08, w: 0.15, h: 0.16, fill: { color: HEX.navy }, line: { color: HEX.navy }, objectName: "flow arrow" });
    }
  });
  // legend
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y: 3.75, w: 0.35, h: 0.2, rectRadius: 0.03, fill: { color: "F4F4F2" }, line: { color: "D9D9D9", width: 1 } });
  s.addText("reused from the authors' replication package", { x: 0.95, y: 3.7, w: 3.2, h: 0.3, fontSize: 10.5, color: HEX.ink2, isTextBox: true, margin: 0 });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 4.3, y: 3.75, w: 0.35, h: 0.2, rectRadius: 0.03, fill: { color: HEX.card }, line: { color: HEX.navy, width: 1.5 } });
  s.addText("new or modified in our project", { x: 4.75, y: 3.7, w: 3.0, h: 0.3, fontSize: 10.5, color: HEX.ink2, isTextBox: true, margin: 0 });
  // output strip
  card(s, 0.5, 4.15, 9.0, 0.88, { name: "output card" });
  s.addText([
    { text: "Output, per model × context: ", options: { bold: true, color: C.text2 } },
    { text: "the corrected Table 5 (RQ1), paired context tests on the same CVEs (RQ2), and labelled false alarms. Everything is computed offline from saved responses, so the notebook's analysis section reruns without API keys." },
  ], { x: 0.65, y: 4.22, w: 8.7, h: 0.74, fontSize: 12, color: C.text1, valign: "middle", isTextBox: true, margin: 0 });
  s.addNotes(NOTE(3));
}

// ---------------------------------------------------------------- 5. system: replication + validity
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "System" });
  title(s, "System: ", "What We Replicated and What We Changed");
  lead(s, "The reproduction matches the paper; deviations and dataset checks are reported, not hidden");
  // left: reproduction stats
  card(s, 0.5, 1.55, 2.7, 3.45, { name: "replication card" });
  s.addText("48 / 48", { x: 0.65, y: 1.65, w: 2.4, h: 0.6, fontSize: 30, bold: true, color: C.text2, isTextBox: true, margin: 0 });
  s.addText("rows of the paper's Tables 4–7 recomputed exactly from the authors' saved outputs", { x: 0.65, y: 2.25, w: 2.4, h: 0.65, fontSize: 11, color: C.text1, isTextBox: true, margin: 0, valign: "top" });
  s.addText("0.985 vs 0.990", { x: 0.65, y: 3.0, w: 2.4, h: 0.45, fontSize: 20, bold: true, color: C.text2, isTextBox: true, margin: 0 });
  s.addText("Haiku 4.5 vulnerable-only F1 in our fresh run vs the paper (C, CO): the vulnerable side reproduces", { x: 0.65, y: 3.45, w: 2.4, h: 0.8, fontSize: 11, color: C.text1, isTextBox: true, margin: 0, valign: "top" });
  s.addText("API cost: $34 of the $45 budget", { x: 0.65, y: 4.45, w: 2.4, h: 0.4, fontSize: 11, bold: true, color: HEX.ink2, isTextBox: true, margin: 0 });
  // middle: deviations table
  const hdr = { bold: true, color: "FFFFFF", fill: { color: HEX.navy }, fontSize: 10.5 };
  const cell = (t, o = {}) => ({ text: t, options: { fontSize: 10, color: "111111", ...o } });
  s.addText("Deviations from the paper's settings", { x: 3.4, y: 1.55, w: 6.1, h: 0.3, fontSize: 12, bold: true, color: C.text1, isTextBox: true, margin: 0 });
  s.addTable([
    [{ text: "Model", options: hdr }, { text: "Paper", options: hdr }, { text: "Ours", options: hdr }, { text: "Why", options: hdr }],
    [cell("Claude Haiku 4.5"), cell("temperature 0"), cell("API default"), cell("the API now rejects temperature for this model")],
    [cell("Gemini 3 Flash"), cell("default thinking"), cell("thinking “low”"), cell("5 of 7 pilot answers spent the 4,096-token budget thinking and gave no label")],
    [cell("GPT-4.1 Mini"), cell("snapshot of the paper"), cell("Azure deployment"), cell("recall on matched CVEs 0.66 vs 0.76 shipped: snapshot drift")],
  ], { x: 3.4, y: 1.9, w: 6.1, colW: [1.25, 1.15, 1.15, 2.55], border: { type: "solid", pt: 0.75, color: "D9D9D9" }, fontFace: "Arial", valign: "middle", rowH: 0.42 });
  s.addText("Is a “fixed” function really safe?", { x: 3.4, y: 3.85, w: 6.1, h: 0.3, fontSize: 12, bold: true, color: C.text1, isTextBox: true, margin: 0 });
  s.addText([
    { text: "Spot check: 28 / 30 valid negatives, 1 valid with caveat, 1 misaligned pair", options: { bullet: true, breakLine: true } },
    { text: "17 / 343 CVEs pair functions with different names; excluding them moves no FPR by more than 1.4 pts", options: { bullet: true, breakLine: true } },
    { text: "Unparsed answers count as errors; scoring only parsed pairs moves no FPR by more than 1.9 pts", options: { bullet: true } },
  ], { x: 3.4, y: 4.15, w: 6.1, h: 0.95, fontSize: 11, color: C.text1, valign: "top", isTextBox: true, margin: 0, paraSpaceAfter: 2 });
  s.addNotes(NOTE(4));
}

// ---------------------------------------------------------------- 6. results: RQ1 headline chart
pres.addSection({ title: "Results" });
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  title(s, "RQ1: ", "Near-Perfect F1, Yet Patched Code Is Flagged");
  lead(s, [{ text: "RQ1: ", options: { color: HEX.blue } }, { text: "With fixed code added, what are each model's precision, FPR, MCC and pair accuracy?" }]);
  const labels = MODELS;
  s.addChart(pres.charts.BAR, [
    { name: "Paper F1 (vulnerable code only)", labels, values: MODELS.map((m) => R(m).paper_C_F1) },
    { name: "False-alarm rate on fixed code", labels, values: MODELS.map((m) => R(m).fpr) },
    { name: "Both versions right (P-C)", labels, values: MODELS.map((m) => R(m)["P-C_rate"]) },
  ], {
    x: 0.4, y: 1.4, w: 6.25, h: 3.75, barDir: "col", barGrouping: "clustered", barGapWidthPct: 60,
    chartColors: [HEX.blue, HEX.orange, HEX.aqua], showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0%",
    valAxisMaxVal: 1.1, valAxisMinVal: 0, valAxisLabelFormatCode: "0%", valAxisMajorUnit: 0.25,
    showLegend: true, legendPos: "b", legendFontSize: 10, legendColor: HEX.ink2, ...quietAxes,
  });
  card(s, 6.85, 1.45, 2.65, 3.6, { name: "takeaway card" });
  s.addText([
    { text: "H1 holds for every model", options: { bold: true, color: C.text2, breakLine: true, fontSize: 13 } },
    { text: " ", options: { breakLine: true, fontSize: 4 } },
    { text: `Haiku 4.5 and Gemini 3 Flash flag ${pct(R("Claude Haiku 4.5").fpr, 1)} and ${pct(R("Gemini 3 Flash").fpr, 1)} of patched functions and get both versions right for only ${pct(R("Claude Haiku 4.5")["P-C_rate"], 1)} and ${pct(R("Gemini 3 Flash")["P-C_rate"], 1)} of CVEs.`, options: { breakLine: true } },
    { text: " ", options: { breakLine: true, fontSize: 4 } },
    { text: "The ranking flips: GPT-4.1 Mini, the paper's weakest model, has the fewest false alarms and the most pairs right.", options: { breakLine: true } },
    { text: " ", options: { breakLine: true, fontSize: 4 } },
    { text: "A high vulnerable-only F1 mostly measures a tendency to say “vulnerable”.", options: { bold: true } },
  ], { x: 7.0, y: 1.58, w: 2.35, h: 3.4, fontSize: 11.5, color: C.text1, valign: "top", isTextBox: true, margin: 0 });
  source(s, "Paper F1: Lira et al. Table 6 (C). Our rates: 343 CO pairs per model. GPT-4.1 Mini from the milestone run.");
  s.addNotes(NOTE(5));
}

// ---------------------------------------------------------------- 7. results: RQ1 table + outcomes
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  title(s, "RQ1: ", "Corrected Table 5 (C, Code-Only)");
  lead(s, [{ text: "RQ1: ", options: { color: HEX.blue } }, { text: "With fixed code added, what are each model's precision, FPR, MCC and pair accuracy?" }]);
  const hdr = { bold: true, color: "FFFFFF", fill: { color: HEX.navy }, fontSize: 9.5, align: "center" };
  const num = (t, o = {}) => ({ text: t, options: { fontSize: 10, align: "center", color: "111111", ...o } });
  const rows = [["Model", "TP", "FN", "FP (fixed flagged)", "TN", "Recall", "Precision", "Paired F1"].map((t, i) => ({ text: t, options: i ? hdr : { ...hdr, align: "left" } }))];
  MODELS.forEach((m) => {
    const r = R(m);
    rows.push([num(m, { align: "left" }), num(String(r.TP)), num(String(r.FN)), num(String(r.FP), { bold: true, color: HEX.orange }), num(String(r.TN)),
      num(r.recall.toFixed(3)), num(r.precision.toFixed(3)), num(r.F1_paired.toFixed(3), { bold: true })]);
  });
  s.addTable(rows, { x: 0.5, y: 1.5, w: 5.5, colW: [1.2, 0.45, 0.45, 0.8, 0.45, 0.62, 0.85, 0.68], border: { type: "solid", pt: 0.75, color: "D9D9D9" }, fontFace: "Arial", valign: "middle", rowH: 0.42 });
  s.addText([
    { text: "Baseline: ", options: { bold: true } },
    { text: "answering “vulnerable” to everything gives recall 1.0, precision 0.5, F1 0.667. Haiku, Gemini and GPT-5 Mini sit at that baseline. GPT-4.1 Mini flags the fewest fixed functions but scores lowest on F1 because it misses 118 real bugs.", options: {} },
  ], { x: 0.5, y: 3.8, w: 5.5, h: 0.85, fontSize: 11, color: C.text1, isTextBox: true, margin: 0, valign: "top" });
  source(s, "C subset, code-only context, 343 pairs per model. GPT-4.1 Mini: milestone run. Unparsed answers count as errors.");
  // outcomes chart
  const labels = [...MODELS].reverse();
  s.addText("What happens to each CVE pair (CO)", { x: 6.15, y: 1.45, w: 3.4, h: 0.3, fontSize: 11.5, bold: true, color: C.text1, isTextBox: true, margin: 0 });
  s.addChart(pres.charts.BAR, [
    { name: "Both right", labels, values: labels.map((m) => R(m)["P-C_rate"]) },
    { name: "Both flagged", labels, values: labels.map((m) => R(m)["P-V_rate"]) },
    { name: "Both cleared", labels, values: labels.map((m) => R(m)["P-B_rate"]) },
    { name: "Reversed", labels, values: labels.map((m) => R(m)["P-R_rate"]) },
  ], {
    x: 6.05, y: 1.75, w: 3.5, h: 3.35, barDir: "bar", barGrouping: "percentStacked", barGapWidthPct: 45,
    chartColors: [HEX.blue, HEX.orange, HEX.aqua, HEX.grey], showValue: false,
    valAxisHidden: true, showLegend: true, legendPos: "b", legendFontSize: 9.5, legendColor: HEX.ink2, ...quietAxes, catAxisLabelFontSize: 10,
  });
  s.addNotes(NOTE(6));
}

// ---------------------------------------------------------------- 8. results: RQ2
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  title(s, "RQ2: ", "More Context Barely Reduces False Alarms");
  lead(s, [{ text: "RQ2: ", options: { color: HEX.blue } }, { text: "Do callers and callees reduce false alarms on fixed code?" }]);
  const ctxs = [["CO", "Code only"], ["CC", "+ Callees"], ["CK", "+ Callers"]];
  const short = { "Claude Haiku 4.5": "Haiku 4.5", "Gemini 3 Flash": "Gemini 3 Flash", "GPT-5 Mini": "GPT-5 Mini", "GPT-4.1 Mini": "GPT-4.1 Mini*" };
  s.addText("Fixed functions flagged as vulnerable (lower is better)", { x: 0.5, y: 1.4, w: 5.4, h: 0.3, fontSize: 11, bold: true, color: C.text1, isTextBox: true, margin: 0 });
  // A picture, not a native chart: Google Slides mangles imported PowerPoint charts. Made by rq2_chart.py.
  s.addImage({ path: "/home/claude/deck/rq2_fpr_by_context.png", x: 0.4, y: 1.72, w: 5.6, h: 3.35, altText: "Bar chart of false-alarm rate on fixed code by context. Haiku 4.5: 97, 95, 97 percent. Gemini 3 Flash: 97, 95, 94. GPT-5 Mini: 87, 79, 70. GPT-4.1 Mini: 56, 45, 45 (code only, plus callees, plus callers).", objectName: "RQ2 chart" });
  const t = D.rq2.find((r) => r.model === "GPT-5 Mini" && r.comparison === "CO-CK" && r.metric === "fixed_alert");
  const rc = D.rq2.find((r) => r.model === "GPT-5 Mini" && r.comparison === "CO-CK" && r.metric === "vulnerable_recall");
  const P = (v) => `${Math.round(100 * v)}%`;
  const rows = [
    { name: "verdict", fill: "F4F4F2", line: "D9D9D9", h: 0.55, runs: [{ text: "Answer: mostly no.", options: { bold: true, fontSize: 14 } }] },
    { name: "haiku gemini", fill: HEX.card, line: HEX.cardLine, h: 0.85, runs: [
      { text: "Haiku 4.5 and Gemini 3 Flash: ", options: { bold: true } },
      { text: "no real change. They flag about 95% of fixed code with or without context." }] },
    { name: "gpt5", fill: "E8F5EE", line: "B9E0CB", h: 0.85, runs: [
      { text: "GPT-5 Mini: ", options: { bold: true } },
      { text: `adding callers cuts false alarms from ${P(t.first_rate)} to ${P(t.second_rate)} (same ${t.N} CVEs, statistically significant).` }] },
    { name: "catch", fill: HEX.warm, line: HEX.warmLine, h: 0.85, runs: [
      { text: "The catch: ", options: { bold: true } },
      { text: `it also catches fewer real bugs (${P(rc.first_rate)} → ${P(rc.second_rate)}). It got more cautious, not better at seeing the fix.` }] },
  ];
  let y = 1.45;
  rows.forEach((r) => {
    card(s, 6.15, y, 3.35, r.h, { name: r.name + " card", fill: r.fill, line: r.line });
    s.addText(r.runs, { x: 6.3, y: y + 0.05, w: 3.05, h: r.h - 0.1, fontSize: 11.5, color: C.text1, valign: "middle", isTextBox: true, margin: 0, objectName: r.name + " text" });
    y += r.h + 0.12;
  });
  source(s, "Bars use every CVE with that context; tests compare the same CVEs (exact McNemar, Holm). *GPT-4.1 Mini: not tested.");
  s.addNotes(NOTE(7));
}

// ---------------------------------------------------------------- 9. results: error analysis
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Results" });
  title(s, "Why Do Models ", "Flag Code That Is Already Fixed?");
  lead(s, "We checked all 946 code-only false alarms: which code does each explanation point at?");
  const A = D.auto_labels;
  const P = (v) => `${Math.round(v)}%`;
  const tot = (k) => { let n = 0, x = 0; Object.values(A).forEach((r) => { n += r.n; x += r.n * r[k] / 100; }); return P(100 * x / n); };
  const mono = { fontFace: "Courier New", fontSize: 10.5 };
  const col = (x, o) => {
    card(s, x, 1.45, 4.4, 2.3, { name: o.key + " card" });
    s.addText([
      { text: o.head, options: { bold: true, fontSize: 14, color: C.text2, breakLine: true } },
      { text: o.who, options: { fontSize: 11, color: HEX.ink2 } },
    ], { x: x + 0.15, y: 1.52, w: 4.1, h: 0.6, valign: "top", isTextBox: true, margin: 0, objectName: o.key + " head" });
    s.addShape(pres.shapes.RECTANGLE, { x: x + 0.15, y: 2.18, w: 4.1, h: 0.72, fill: { color: "FFFFFF" }, line: { color: "D9D9D9", width: 0.75 }, objectName: o.key + " code box" });
    s.addText([
      { text: "Before:  ", options: { bold: true, fontSize: 10, color: HEX.orange } }, { text: o.before, options: { ...mono, breakLine: true } },
      { text: "Fixed:   ", options: { bold: true, fontSize: 10, color: "13805A" } }, { text: o.after, options: mono },
    ], { x: x + 0.25, y: 2.2, w: 3.95, h: 0.68, color: C.text1, valign: "middle", isTextBox: true, margin: 0, paraSpaceAfter: 2, objectName: o.key + " code" });
    s.addText([
      { text: o.cve + "  ", options: { bold: true, color: HEX.ink2, fontSize: 10 } },
      { text: o.said },
    ], { x: x + 0.15, y: 2.98, w: 4.1, h: 0.75, fontSize: 11.5, color: C.text1, valign: "top", isTextBox: true, margin: 0, objectName: o.key + " said" });
  };
  col(0.5, { key: "fix", head: "1. Quotes the fix, still calls it vulnerable", who: `${tot("fix")} of all false alarms`,
    before: "UINT16 count = number * 2;", after: "UINT32 count = number * 2;", cve: "CVE-2018-8786",
    said: "The fix widens the counter to 32 bits. Haiku quotes the new line and still calls it an integer overflow." });
  col(5.1, { key: "other", head: "2. Points at unchanged code instead", who: `${tot("other")} of all false alarms: the most common case`,
    before: "fchmod(fd, 0666 - umask)", after: "fchmod(fd, 0666 & ~umask)", cve: "CVE-2013-6412",
    said: "GPT-5 Mini accepts the fixed line, then reports a file race elsewhere that we could not confirm." });
  // counts table: all false alarms, automatic labels
  const h = { bold: true, fontSize: 10, color: "FFFFFF", fill: { color: HEX.navy }, align: "center" };
  const c = (t, o = {}) => ({ text: t, options: { fontSize: 10.5, align: "center", color: "111111", ...o } });
  const order = ["Claude Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini"];
  s.addTable([
    [{ text: "Model", options: { ...h, align: "left" } }, { text: "False alarms", options: h }, { text: "Quotes the fix", options: h }, { text: "Unchanged code", options: h }, { text: "No code", options: h }],
    ...order.map((m) => [c(m, { align: "left" }), c(String(A[m].n)), c(P(A[m].fix)), c(P(A[m].other)), c(P(A[m].none))]),
  ], { x: 0.5, y: 3.95, w: 5.2, colW: [1.5, 0.95, 1.05, 1.1, 0.6], rowH: 0.27, border: { type: "solid", pt: 0.75, color: "D9D9D9" }, fontFace: "Arial", valign: "middle", margin: [0.02, 0.06, 0.02, 0.06] });
  card(s, 5.9, 3.95, 3.6, 1.1, { name: "memorisation card", fill: "F4F4F2", line: "D9D9D9" });
  s.addText([
    { text: "Likely amplifier: the prompt. ", options: { bold: true } },
    { text: "Its instructions say “Explain where the vulnerability is located”, assuming one exists (untested). ", options: { breakLine: true } },
    { text: "Not memorisation: ", options: { bold: true } },
    { text: "models rarely name the CVE." },
  ], { x: 6.05, y: 4.0, w: 3.3, h: 1.0, fontSize: 10.5, color: C.text1, valign: "middle", paraSpaceAfter: 3, isTextBox: true, margin: 0 });
  const anyFix = Object.values(D.auto_labels_any);
  source(s, `Automatic: code quoted in each explanation matched to the patched lines; agrees with 17 of 24 hand labels. Counting any quote of the fix: ${Math.round(Math.min(...anyFix))}–${Math.round(Math.max(...anyFix))}%.`);
  s.addNotes(NOTE(8));
}

// ---------------------------------------------------------------- 10. future work
pres.addSection({ title: "Future work" });
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Future work" });
  title(s, "Recommended ", "Future Work");
  lead(s, "Next goal: a detector that is right on both sides of the patch, judged on a benchmark built for that");
  const items = [
    ["1", "Make the patch visible", "Diff-aware prompting: show both versions or the diff and ask whether the specific flaw is still reachable.", "~$100 API; 2 weeks"],
    ["2", "Verify before alerting", "Agentic triage: the model must back each alert with a static-analysis query, sanitizer run or PoC input.", "Containerised builds of ~300 projects; 1 engineer-month"],
    ["3", "Calibrate the threshold", "Score with log-probabilities or self-consistency and pick an operating point on paired data, not a yes/no.", "Open-weight models on 1–2 GPUs"],
    ["4", "A human-validated paired benchmark", "All languages, PrimeVul/JitVul pairs, post-cutoff CVEs, two security experts per pair.", "2 annotators × 6 weeks for ~1,000 pairs"],
    ["5", "Train on pairs", "Contrastive fine-tuning of an open code model on vulnerable/fixed pairs.", "8×A100 for ~3 days"],
  ];
  items.forEach(([n, head, body, res], i) => {
    const y = 1.5 + i * 0.73;
    s.addShape(pres.shapes.OVAL, { x: 0.5, y: y + 0.08, w: 0.42, h: 0.42, fill: { color: HEX.navy }, line: { color: HEX.navy } });
    s.addText(n, { x: 0.5, y: y + 0.08, w: 0.42, h: 0.42, fontSize: 13, bold: true, color: "FFFFFF", align: "center", valign: "middle", isTextBox: true, margin: 0 });
    s.addText([{ text: head + "  ", options: { bold: true, color: C.text2 } }, { text: body }], { x: 1.1, y, w: 5.65, h: 0.6, fontSize: 11.5, color: C.text1, valign: "middle", isTextBox: true, margin: 0 });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 6.95, y: y + 0.04, w: 2.55, h: 0.52, rectRadius: 0.06, fill: { color: "F4F4F2" }, line: { color: "D9D9D9", width: 0.75 } });
    s.addText(res, { x: 7.05, y: y + 0.04, w: 2.35, h: 0.52, fontSize: 10, color: HEX.ink2, valign: "middle", isTextBox: true, margin: 0 });
  });
  s.addText("Resources needed", { x: 6.95, y: 1.2, w: 2.55, h: 0.28, fontSize: 10.5, bold: true, color: HEX.ink2, isTextBox: true, margin: 0 });
  s.addNotes(NOTE(9));
}

// ---------------------------------------------------------------- 11. justification
{
  const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: "Future work" });
  title(s, "Justification ", "for Future Work");
  lead(s, "Each next step answers a specific failure we measured in the working system");
  const hdr = { bold: true, color: "FFFFFF", fill: { color: HEX.navy }, fontSize: 11 };
  const c = (t, o = {}) => ({ text: t, options: { fontSize: 10.5, color: "111111", ...o } });
  s.addTable([
    [{ text: "Evidence from our system", options: hdr }, { text: "Next step", options: hdr }],
    [c(`${pct(R("Claude Haiku 4.5")["P-V_rate"], 0)} / ${pct(R("Gemini 3 Flash")["P-V_rate"], 0)} of pairs are flagged on both sides by Haiku / Gemini; about 28% of false alarms quote the fix itself`), c("1  Diff-aware prompting", { bold: true, color: HEX.navy })],
    [c("71% of false alarms point at unchanged code (GPT-5 Mini: 79%), with claims we could not confirm"), c("2  Verify before alerting", { bold: true, color: HEX.navy })],
    [c("Context lowered GPT-5 Mini's false alarms by 15 pts but recall by ~8 pts: the model shifted its threshold"), c("3  Calibrate the threshold", { bold: true, color: HEX.navy })],
    [c("17 of 343 CVEs have misaligned/renamed functions; spot check and labels by one reviewer; Gemini names the right CVE 17 times"), c("4  Human-validated, post-cutoff benchmark", { bold: true, color: HEX.navy })],
    [c(`Every model's MCC is near 0 (highest: ${bestMcc.v.toFixed(2)}, ${bestMcc.m} ${bestMcc.c}): prompting alone barely separates the two versions`), c("5  Train on pairs", { bold: true, color: HEX.navy })],
  ], { x: 0.5, y: 1.5, w: 9.0, colW: [6.2, 2.8], border: { type: "solid", pt: 0.75, color: "D9D9D9" }, fontFace: "Arial", valign: "middle", rowH: 0.56 });
  source(s, "All evidence: results/final/*.csv and docs/final_results.md in the project repository; analysis reproduced in the notebook's Step 6.");
  s.addNotes(NOTE(10));
}

(async () => {
  await pres.writeFile({ fileName: "/home/claude/deck/Final_presentation_slides.pptx" });
  await applyTheme("/home/claude/deck/Final_presentation_slides.pptx", THEME);
  await plainCategoryLabels("/home/claude/deck/Final_presentation_slides.pptx");
  console.log("written");
})();
