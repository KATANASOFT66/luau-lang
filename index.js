/*
 * Luau Deobfuscator — executes the actual string decoding
 * logic that WeAreDevs (and similar) obfuscators use:
 *
 * 1) Decimal-escape strings → raw bytes (these are base64 chars)
 * 2) Index shuffles via ipairs swap loops
 * 3) Accessor function y(n) = r[n - offset]
 * 4) Base64 decoding of the resulting strings
 * 5) VM opcode table + constant analysis
 *
 * This runs entirely in-browser, no server needed.
 */

const S = {
  logs: [], strings: [], resolved: {}, output: '',
  stats: { score:0, strN:0, decN:0, b64N:0, funcs:0, patterns:0, methods: new Set() }
};

// ── Tabs ──
document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
    document.querySelectorAll('.tc').forEach(x=>x.classList.remove('on'));
    t.classList.add('on');
    document.getElementById('t-'+t.dataset.t).classList.add('on');
  };
});
document.getElementById('ci').addEventListener('input', uSz);
function uSz(){ const v=document.getElementById('ci').value; document.getElementById('sz').textContent=v.length>1024?(v.length/1024).toFixed(1)+' KB':v.length+' B'; }

function pg(p){ document.getElementById('pg').style.width=p+'%'; }
function e(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function tr(s,n=80){ return s.length>n?s.slice(0,n)+'…':s; }
function L(c,m,l='INFO'){ S.logs.push({c,m,l}); }

// ═════════════════════════════════════════
//  STEP 1: Decode \DDD decimal escapes
//  In Lua/Luau, "\073" = char(73) = 'I'
//  The obfuscator encodes base64 chars this way
// ═════════════════════════════════════════
function decEsc(s) {
  return s.replace(/\\(\d{1,3})/g, (_,d) => {
    const c = parseInt(d, 10);
    return (c >= 0 && c <= 255) ? String.fromCharCode(c) : _;
  }).replace(/\\x([0-9a-fA-F]{2})/g, (_,h) => {
    return String.fromCharCode(parseInt(h,16));
  }).replace(/\\n/g,'\n').replace(/\\t/g,'\t').replace(/\\r/g,'\r')
    .replace(/\\\\/g,'\\').replace(/\\"/g,'"').replace(/\\'/g,"'");
}

// ═════════════════════════════════════════
//  STEP 2: Base64 decode
//  After decimal-escape decode, each string
//  in the table is a base64-encoded value
// ═════════════════════════════════════════
function b64dec(s) {
  try {
    // Standard base64
    const cleaned = s.replace(/[^A-Za-z0-9+/=]/g, '');
    if (cleaned.length < 2) return null;
    if (cleaned.length % 4 !== 0 && !cleaned.includes('=')) {
      // Pad if needed
      const padded = cleaned + '='.repeat((4 - cleaned.length % 4) % 4);
      return atob(padded);
    }
    return atob(cleaned);
  } catch(e) { return null; }
}

function isPrint(s) {
  if (!s || s.length === 0) return false;
  let p = 0;
  for (let i = 0; i < Math.min(s.length, 50); i++) {
    const c = s.charCodeAt(i);
    if ((c >= 32 && c <= 126) || c === 10 || c === 13 || c === 9) p++;
  }
  return p / Math.min(s.length, 50) > 0.6;
}

// ═════════════════════════════════════════
//  Extract the string table from source
// ═════════════════════════════════════════
function extractTable(src) {
  const results = [];

  // Find: local r={...} — the main string table
  // Match opening brace after "local X={"
  // We need to handle nested braces and semicolons as separators
  const startMatch = src.match(/local\s+(\w)\s*=\s*\{/);
  if (!startMatch) {
    L('TABLE', 'No string table found with "local X={" pattern', 'WARN');
    // Try alternate: just find the first big table
    return extractStringsGlobal(src);
  }

  const varName = startMatch[1];
  const startIdx = startMatch.index + startMatch[0].length;
  L('TABLE', `Found table variable: "${varName}" at position ${startMatch.index}`, 'OK');

  // Find matching closing brace
  let depth = 1;
  let i = startIdx;
  while (i < src.length && depth > 0) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') depth--;
    if (depth > 0) i++;
  }
  const tableBody = src.substring(startIdx, i);

  // Extract each string entry
  const re = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g;
  let m, idx = 0;
  while ((m = re.exec(tableBody)) !== null) {
    idx++;
    const raw = m[1] !== undefined ? m[1] : m[2];
    const step1 = decEsc(raw);  // decode \073 -> 'I' etc
    const step2 = b64dec(step1); // base64 decode

    results.push({
      i: idx,
      raw,              // original escaped
      escaped: step1,   // after decimal-escape decode (= base64 string)
      decoded: step2,   // after base64 decode (= actual value)
      isB64: step2 !== null && step2 !== step1,
      isPrintable: step2 ? isPrint(step2) : isPrint(step1)
    });
  }

  L('TABLE', `Extracted ${results.length} string entries`, 'OK');
  return { varName, results };
}

function extractStringsGlobal(src) {
  const results = [];
  const re = /"((?:\\[\d]{2,3}){3,}[^"]*)"/g;
  let m, idx = 0;
  while ((m = re.exec(src)) !== null) {
    idx++;
    const raw = m[1];
    const step1 = decEsc(raw);
    const step2 = b64dec(step1);
    results.push({
      i: idx, raw, escaped: step1,
      decoded: step2,
      isB64: step2 !== null && step2 !== step1,
      isPrintable: step2 ? isPrint(step2) : isPrint(step1)
    });
  }
  return { varName: '?', results };
}

// ═════════════════════════════════════════
//  Extract and apply shuffle operations
// ═════════════════════════════════════════
function extractShuffles(src) {
  const ops = [];
  // Find: for y,F in ipairs({{expr,expr},{expr,expr},...}) do while ...
  const block = src.match(/for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{([\s\S]*?)\}\s*\)\s*do\s+while/);
  if (!block) return ops;

  const inner = block[1];
  const pairRe = /\{([^}]+)\}/g;
  let m;
  while ((m = pairRe.exec(inner)) !== null) {
    const parts = m[1].split(',');
    if (parts.length >= 2) {
      const a = safeEval(parts[0].trim());
      const b = safeEval(parts[1].trim());
      if (a !== null && b !== null) ops.push([a, b]);
    }
  }
  if (ops.length) L('SHUFFLE', `Found ${ops.length} swap operations`, 'OK');
  return ops;
}

function safeEval(expr) {
  expr = expr.replace(/\s/g, '');
  if (!/^[\d+\-*()]+$/.test(expr)) return null;
  try {
    const r = Function('"use strict";return('+expr+')')();
    return typeof r === 'number' && isFinite(r) ? Math.round(r) : null;
  } catch { return null; }
}

function applyShuffle(arr, ops) {
  const a = [...arr];
  for (const [sA, sB] of ops) {
    let lo = sA, hi = sB;
    while (lo < hi) {
      const iA = lo - 1, iB = hi - 1; // Lua 1-indexed → JS 0-indexed
      if (iA >= 0 && iA < a.length && iB >= 0 && iB < a.length) {
        [a[iA], a[iB]] = [a[iB], a[iA]];
      }
      lo++; hi--;
    }
  }
  return a.map((s, i) => ({ ...s, i: i + 1 }));
}

// ═════════════════════════════════════════
//  Find accessor function offset
//  function y(y) return r[y-(EXPR)] end
// ═════════════════════════════════════════
function findOffset(src) {
  // Pattern variations:
  // return r[y-(-393492+446576)]
  // return r[y-(expr)]
  const patterns = [
    /function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[\s*\w+\s*-\s*\(([^)]+)\)\s*\]/,
    /function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[\s*\w+\s*\+\s*\(([^)]+)\)\s*\]/,
    /function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[\s*\w+\s*-\s*([^\]]+)\]/
  ];

  for (let pi = 0; pi < patterns.length; pi++) {
    const m = src.match(patterns[pi]);
    if (m) {
      const fnName = m[1];
      const val = safeEval(m[2]);
      if (val !== null) {
        const offset = pi === 1 ? -val : val; // + means negative offset
        L('OFFSET', `Accessor "${fnName}", offset = ${offset}`, 'OK');
        return { fnName, offset };
      }
    }
  }
  return null;
}

// ═════════════════════════════════════════
//  Resolve all y(expr) → actual string
// ═════════════════════════════════════════
function resolveAll(src, strings, acc) {
  if (!acc) return {};
  const map = {};
  const re = new RegExp(acc.fnName.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + '\\s*\\(([^)]+)\\)', 'g');
  let m;
  while ((m = re.exec(src)) !== null) {
    const v = safeEval(m[1].trim());
    if (v !== null) {
      const idx = v - acc.offset; // 1-indexed
      if (idx >= 1 && idx <= strings.length) {
        const s = strings[idx - 1];
        const val = s.decoded || s.escaped;
        map[m[0]] = { call: m[0], idx, value: val, argExpr: m[1].trim(), argVal: v };
      }
    }
  }
  L('RESOLVE', `Resolved ${Object.keys(map).length} accessor calls`, 'OK');
  return map;
}

// ═════════════════════════════════════════
//  Detect patterns / score
// ═════════════════════════════════════════
function detectPatterns(src) {
  const p = [];
  const checks = [
    [/return\s*\(\s*function\s*\(\.\.\.\)/g, 'Self-executing wrapper', 15],
    [/\\(\d{3})/g, 'Decimal escape encoding', 10],
    [/for\s+\w+\s*,\s*\w+\s+in\s+ipairs[\s\S]{0,50}while/g, 'Index shuffle loop', 12],
    [/getfenv/g, 'getfenv access', 8],
    [/setmetatable/g, 'Metatable manipulation', 5],
    [/newproxy/g, 'newproxy (VM trick)', 10],
    [/while\s+\w+\s+do\s+if\s+\w+\s*</g, 'VM dispatch loop', 15],
    [/loadstring\s+or\s+load/g, 'Dynamic code loading', 12],
    [/string\.char/g, 'string.char', 3],
    [/string\.byte/g, 'string.byte', 3],
    [/string\.sub/g, 'string.sub', 3],
    [/select\s*\(\s*["']#/g, 'Vararg counting', 4],
    [/bit32/g, 'Bitwise ops', 5],
    [/wearedevs/i, 'WeAreDevs signature', 0],
    [/v\d+\.\d+\.\d+/g, 'Version tag', 0],
    [/math\.floor/g, 'math.floor', 2],
    [/unpack\s+or\s+table/g, 'unpack compat', 3],
  ];
  let score = 0;
  for (const [re, name, w] of checks) {
    const matches = src.match(re);
    if (matches) {
      p.push({ name, count: matches.length, weight: w });
      score += Math.min(w, matches.length * Math.ceil(w / 3));
    }
  }
  return { patterns: p, score: Math.min(100, score) };
}

// ═════════════════════════════════════════
//  Build final readable output
// ═════════════════════════════════════════
function buildOutput(strings, resolved) {
  let out = '';
  out += '-- ══════════════════════════════════════\n';
  out += '-- DECODED STRING TABLE\n';
  out += '-- Each string was: decimal-escaped → base64\n';
  out += '-- ══════════════════════════════════════\n\n';

  for (const s of strings) {
    const val = s.decoded || s.escaped;
    const safe = val.replace(/\\/g,'\\\\').replace(/"/g,'\\"')
                    .replace(/\n/g,'\\n').replace(/\r/g,'\\r').replace(/\t/g,'\\t');
    const b64note = s.isB64 ? ' (base64 decoded)' : '';
    out += `r[${s.i}] = "${safe}"${b64note}\n`;
  }

  // Show resolved accessor calls
  const rEntries = Object.values(resolved);
  if (rEntries.length > 0) {
    out += '\n-- ══════════════════════════════════════\n';
    out += '-- RESOLVED ACCESSOR CALLS\n';
    out += `-- ${rEntries.length} calls resolved\n`;
    out += '-- ══════════════════════════════════════\n\n';
    for (const r of rEntries) {
      const safe = r.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')
                          .replace(/\n/g,'\\n').replace(/\r/g,'\\r');
      out += `${r.call}  -->  "${safe}"  (index ${r.idx})\n`;
    }
  }

  // Try to identify what the script does
  out += '\n-- ══════════════════════════════════════\n';
  out += '-- SCRIPT ANALYSIS\n';
  out += '-- ══════════════════════════════════════\n\n';

  const allVals = strings.map(s => s.decoded || s.escaped).filter(Boolean);
  const apiCalls = allVals.filter(v => v.includes('.') || v.includes(':'));
  const properties = allVals.filter(v => /^[A-Z][a-zA-Z]+$/.test(v));
  const methods = allVals.filter(v => /^[a-z][a-zA-Z]+$/.test(v) && v.length > 2);

  if (apiCalls.length) {
    out += '-- API calls found:\n';
    for (const a of apiCalls) out += `--   ${a}\n`;
  }
  if (properties.length) {
    out += '-- Properties:\n';
    for (const p of properties) out += `--   ${p}\n`;
  }
  if (methods.length) {
    out += '-- Methods/names:\n';
    for (const m of methods) out += `--   ${m}\n`;
  }

  return out;
}

// ═════════════════════════════════════════
//  MAIN RUNNER
// ═════════════════════════════════════════
function run() {
  const src = document.getElementById('ci').value.trim();
  if (!src) return alert('Paste code first');

  // Reset
  S.logs=[]; S.strings=[]; S.resolved={}; S.output='';
  S.stats={score:0,strN:0,decN:0,b64N:0,funcs:0,patterns:0,methods:new Set()};
  pg(5);

  setTimeout(() => {
    try { doRun(src); } catch(e) { L('ERROR',e.message,'ERR'); console.error(e); }
    renderAll();
    pg(100);
    setTimeout(()=>pg(0), 1200);
  }, 30);
}

function doRun(src) {
  L('INIT','════════════════════════════════════');
  L('INIT','Luau Deobfuscator — Starting');
  L('INIT',`Input: ${src.length} bytes`);
  L('INIT','════════════════════════════════════');

  pg(10);

  // 1. Detect obfuscator
  L('STEP','▶ Step 1: Pattern detection');
  const { patterns, score } = detectPatterns(src);
  S.stats.score = score;
  S.stats.patterns = patterns.length;
  for (const p of patterns) {
    const ic = p.weight >= 10 ? '🔴' : p.weight >= 5 ? '🟡' : '🟢';
    L('DETECT', `${ic} ${p.name} (×${p.count})`);
  }
  if (src.toLowerCase().includes('wearedevs')) {
    S.stats.methods.add('WeAreDevs Obfuscator');
    L('DETECT', '✓ Identified as WeAreDevs obfuscator', 'OK');
  }

  pg(20);

  // 2. Extract string table
  L('STEP','▶ Step 2: String table extraction + decode');
  const { varName, results: rawStrings } = extractTable(src);
  S.stats.strN = rawStrings.length;

  let b64Count = 0;
  for (const s of rawStrings) {
    if (s.isB64) { b64Count++; S.stats.methods.add('Base64'); }
    S.stats.decN++;
    S.stats.methods.add('Decimal Escapes');
  }
  S.stats.b64N = b64Count;
  L('DECODE', `${rawStrings.length} strings extracted, ${b64Count} base64 decoded`, 'OK');

  pg(40);

  // 3. Shuffle
  L('STEP','▶ Step 3: Index shuffle resolution');
  const shuffleOps = extractShuffles(src);
  let finalStrings;
  if (shuffleOps.length > 0) {
    finalStrings = applyShuffle(rawStrings, shuffleOps);
    S.stats.methods.add('Index Shuffle');
  } else {
    finalStrings = rawStrings;
    L('SHUFFLE','No shuffle found','INFO');
  }
  S.strings = finalStrings;

  // Log first few decoded strings
  for (const s of finalStrings.slice(0, 10)) {
    const val = s.decoded || s.escaped;
    L('STRING', `[${s.i}] "${tr(val, 60)}"${s.isB64 ? ' (b64)' : ''}`, 'OK');
  }
  if (finalStrings.length > 10) L('STRING', `... and ${finalStrings.length - 10} more`);

  pg(60);

  // 4. Accessor
  L('STEP','▶ Step 4: Accessor function resolution');
  const acc = findOffset(src);
  let resolved = {};
  if (acc) {
    resolved = resolveAll(src, finalStrings, acc);
    S.resolved = resolved;
    const entries = Object.values(resolved);
    for (const r of entries.slice(0, 10)) {
      L('RESOLVE', `${r.call} → "${tr(r.value, 50)}"`, 'OK');
    }
    if (entries.length > 10) L('RESOLVE', `... and ${entries.length - 10} more`);
  } else {
    L('OFFSET', 'Accessor offset not found — showing raw index mapping', 'WARN');
  }

  pg(80);

  // 5. Build output
  L('STEP','▶ Step 5: Building output');
  S.output = buildOutput(finalStrings, resolved);

  // Summary
  L('DONE','════════════════════════════════════');
  L('DONE',`Strings: ${S.stats.strN} total, ${S.stats.b64N} base64 decoded`);
  L('DONE',`Accessor calls resolved: ${Object.keys(resolved).length}`);
  L('DONE',`Obfuscation score: ${S.stats.score}/100`);
  L('DONE',`Methods: ${[...S.stats.methods].join(', ')}`);
  L('DONE','════════════════════════════════════');
}

// ═════════════════════════════════════════
//  RENDERERS
// ═════════════════════════════════════════
function renderAll() {
  renderOv(); renderSt(); renderLg(); renderDc();
  document.getElementById('oi').textContent = `${S.strings.length} strings`;
}

function renderOv() {
  document.getElementById('es').style.display='none';
  const el = document.getElementById('ovo');
  el.style.display='block';
  const sc = S.stats.score;
  const col = sc>=70?'var(--rd)':sc>=40?'var(--or)':sc>=15?'var(--ac)':'var(--gn)';
  const lab = sc>=70?'Heavy VM':sc>=40?'Moderate':sc>=15?'Light':'Minimal';

  el.innerHTML = `<div class="oa">
    <div class="sg">
      <div class="sc"><div class="sl">Obfuscation</div><div class="sv" style="color:${col}">${sc}/100</div><div class="ss">${lab}</div></div>
      <div class="sc"><div class="sl">Strings</div><div class="sv" style="color:var(--gn)">${S.stats.strN}</div><div class="ss">${S.stats.b64N} base64 decoded</div></div>
      <div class="sc"><div class="sl">Resolved Calls</div><div class="sv" style="color:var(--ac)">${Object.keys(S.resolved).length}</div><div class="ss">accessor → string</div></div>
      <div class="sc"><div class="sl">Patterns</div><div class="sv" style="color:var(--pr)">${S.stats.patterns}</div><div class="ss">VM signatures</div></div>
    </div>
    ${S.stats.methods.size?`<div class="sec" style="margin-top:10px"><div class="sh"><span class="dot do_"></span>Methods</div><div class="sb">${[...S.stats.methods].map(m=>`<span class="sm" style="margin:2px">${e(m)}</span>`).join(' ')}</div></div>`:''}
    <div class="sec" style="margin-top:10px">
      <div class="sh"><span class="dot dg"></span>Decoded Strings Preview</div>
      <div class="sb">${S.strings.slice(0,25).map(s=>{
        const v=s.decoded||s.escaped;
        return `<div class="sr"><span class="si">${s.i}</span>${s.isB64?'<span class="sm">b64</span>':'<span class="sm" style="background:rgba(107,122,141,.1);color:var(--d)">esc</span>'}<span class="sd">${e(tr(v,90))}</span></div>`;
      }).join('')||'<span style="color:var(--d)">None</span>'}</div>
    </div>
  </div>`;
}

function renderSt() {
  const el = document.getElementById('sto');
  if (!S.strings.length) { el.innerHTML='<div class="emp"><div class="ic">🔤</div></div>'; return; }
  let h='';
  for (const s of S.strings) {
    const v = s.decoded || s.escaped;
    h+=`<div class="sr" data-f="${e((v+s.raw+s.escaped).toLowerCase())}">
      <span class="si">${s.i}</span>
      ${s.isB64?'<span class="sm">b64</span>':'<span class="sm" style="background:rgba(107,122,141,.1);color:var(--d)">esc</span>'}
      <span style="color:var(--or);flex:1;word-break:break-all;font-size:.85em" title="After escape decode">${e(tr(s.escaped,40))}</span>
      <span style="color:var(--d)">→</span>
      <span class="sd" title="Final value">${e(tr(v,50))}</span>
    </div>`;
  }
  el.innerHTML=h;
}

function renderLg() {
  const el = document.getElementById('lgo');
  let h='';
  for (const l of S.logs) {
    const c = l.l==='OK'?'to':l.l==='WARN'?'tw':l.l==='ERR'?'te':'ti';
    h+=`<div class="ll" data-f="${e((l.c+' '+l.m).toLowerCase())}"><span class="lt ${c}">${e(l.c.slice(0,7))}</span><span>${e(l.m)}</span></div>`;
  }
  el.innerHTML=h||'<div class="emp"><div class="ic">📋</div></div>';
}

function renderDc() {
  const el = document.getElementById('dco');
  if (!S.output) { el.innerHTML='<div class="emp"><div class="ic">✨</div></div>'; return; }
  el.innerHTML=`<div style="padding:6px 10px;display:flex;gap:5px;border-bottom:1px solid var(--bd)">
    <button class="cpb" onclick="cpAll()">📋 Copy All</button>
    <button class="cpb" onclick="cpStr()">📋 Strings Only</button>
    <span style="font-size:.68em;color:var(--d);display:flex;align-items:center">${S.strings.length} strings</span>
  </div>
  <div class="cb" style="margin:0;border:none;border-radius:0;max-height:calc(100vh - 140px);overflow:auto">${hlLua(S.output)}</div>`;
}

function hlLua(code) {
  let h = e(code);
  h = h.replace(/(--[^\n]*)/g,'<span class="hlc">$1</span>');
  h = h.replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)/g,'<span class="hls">$1</span>');
  h = h.replace(/\b(\d+(?:\.\d+)?)\b/g,'<span class="hln">$1</span>');
  const kw=['local','function','return','end','if','then','else','elseif','for','while','do','repeat','until','break','in','or','and','not','true','false','nil'];
  for (const k of kw) h=h.replace(new RegExp('\\b('+k+')\\b','g'),'<span class="hlk">$1</span>');
  return h;
}

// ── UI Helpers ──
function filt(t) {
  const q = document.getElementById(t==='st'?'sf':'lf').value.toLowerCase();
  const sel = t==='st'?'#sto .sr':'#lgo .ll';
  document.querySelectorAll(sel).forEach(r => {
    r.style.display = (r.dataset.f||'').includes(q)?'':'none';
  });
}

function cpAll() {
  navigator.clipboard.writeText(S.output);
  const b=event.target; const o=b.textContent; b.textContent='✅ Copied!'; b.style.color='var(--gn)'; setTimeout(()=>{b.textContent=o;b.style.color='';},1000);
}

function cpStr() {
  let t='';
  for (const s of S.strings) { t+=`[${s.i}] ${s.decoded||s.escaped}\n`; }
  navigator.clipboard.writeText(t);
  const b=event.target; const o=b.textContent; b.textContent='✅ Copied!'; b.style.color='var(--gn)'; setTimeout(()=>{b.textContent=o;b.style.color='';},1000);
}

function clearAll() {
  document.getElementById('ci').value='';
  S.logs=[]; S.strings=[]; S.output=''; S.resolved={};
  document.getElementById('es').style.display='';
  document.getElementById('ovo').style.display='none';
  document.getElementById('sto').innerHTML='';
  document.getElementById('lgo').innerHTML='';
  document.getElementById('dco').innerHTML='';
  document.getElementById('oi').textContent='—';
  uSz();
}

function exportAll() {
  if (!S.strings.length && !S.logs.length) return alert('Nothing to export');
  let t='=== Luau Deobfuscation Report ===\n\n';
  t+='== DECODED STRINGS ==\n';
  for (const s of S.strings) t+=`[${s.i}] ${s.decoded||s.escaped}\n`;
  t+='\n== LOG ==\n';
  for (const l of S.logs) t+=`[${l.l}][${l.c}] ${l.m}\n`;
  t+='\n== OUTPUT ==\n'+S.output;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([t],{type:'text/plain'}));
  a.download='deobf_report.txt'; a.click();
}

function loadSample() {
  // Load the user's actual obfuscated code as sample
  document.getElementById('ci').value = String.raw`--[[ v1.0.0 https://wearedevs.net/obfuscator ]] return(function(...)local r={"\073\074\051\087\115\074\078\061","\083\107\113\047\068\108\061\061";"\104\086\088\119\081\057\055\052";"\085\080\073\107\115\078\055\111\100\074\088\119\078\107\107\078\081\054\118\061";"\098\049\106\061";"\078\113\065\080\107\078\047\080\068\074\049\107\100\097\051\090";"\100\054\070\106\066\120\070\066\100\107\073\070\073\122\109\056\088\103\061\061";"\115\097\102\061";"\081\083\070\120\088\116\079\057\083\054\047\101\100\113\107\049\073\074\118\061";"\104\067\107\054\115\057\107\054\072\080\088\110\072\101\047\070";"\072\052\070\054\068\118\061\061","\088\054\049\078\078\067\065\053\072\054\076\086\115\051\110\068\118\108\061\061","\083\078\105\070\115\120\107\114\115\054\102\116\100\077\068\100\115\118\061\061";"\057\102\088\101\057\051\121\052\068\067\051\069\118\122\049\079","\068\067\116\110\073\074\049\106";}end)()`;
  uSz();
}

uSz();
