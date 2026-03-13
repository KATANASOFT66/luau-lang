// ═══════════════════════════════════════════════════
//  Luau VM Deobfuscator — WeAreDevs / Generic
//  Performs static analysis + string table extraction
//  + octal/hex/decimal escape decoding + VM pattern
//  detection + structure analysis
// ═══════════════════════════════════════════════════

const G = {
    logs: [],
    strings: [],
    decoded: [],
    structure: { funcs: [], locals: [], tables: [], meta: [], envCalls: [] },
    stats: { obfScore:0, strCount:0, decCount:0, funcs:0, tables:0, patterns:0, methods: new Set() },
    output: ''
};

// ── Tab switching ──
document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        document.getElementById('tab-' + t.dataset.tab).classList.add('active');
    });
});

document.getElementById('codeIn').addEventListener('input', updateSize);
function updateSize() {
    const v = document.getElementById('codeIn').value;
    document.getElementById('inSize').textContent = v.length > 1024 ? (v.length/1024).toFixed(1)+' KB' : v.length+' B';
}

function prog(p) { document.getElementById('prog').style.width = p+'%'; }
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function trunc(s, n=80) { return s.length > n ? s.slice(0,n)+'…' : s; }

function log(cat, msg, level='INFO') {
    G.logs.push({ cat, msg, level });
}

// ═══════════════════════════════════
//  CORE: Octal escape decoder
//  This is the KEY for WeAreDevs obfuscator
//  It uses \DDD octal codes in strings
// ═══════════════════════════════════
function decodeOctalEscapes(str) {
    // Matches \DDD where D are digits (Lua octal/decimal byte escapes)
    return str.replace(/\\(\d{1,3})/g, (match, digits) => {
        const code = parseInt(digits, 10); // Lua uses DECIMAL not octal for \DDD
        if (code >= 0 && code <= 255) {
            return String.fromCharCode(code);
        }
        return match;
    });
}

function decodeHexEscapes(str) {
    return str.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
    });
}

function decodeAllEscapes(str) {
    let r = str;
    r = decodeOctalEscapes(r);
    r = decodeHexEscapes(r);
    r = r.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r')
         .replace(/\\\\/g, '\\').replace(/\\"/g, '"').replace(/\\'/g, "'");
    return r;
}

// ═══════════════════════════════════
//  Extract the string table r={...}
//  This is the main obfuscation layer
// ═══════════════════════════════════
function extractStringTable(source) {
    const results = [];

    // Pattern 1: r={"str1","str2",...} or r={"str1";"str2";...}
    // The WeAreDevs obfuscator stores all strings in a table using decimal escapes
    const tablePattern = /local\s+(\w)\s*=\s*\{([\s\S]*?)\}(?:\s*for\s|\s*local\s)/;
    const match = source.match(tablePattern);

    if (match) {
        const varName = match[1];
        const tableContent = match[2];
        log('EXTRACT', `Found string table variable: "${varName}"`, 'OK');

        // Extract individual string entries - handle both "..." and '...'
        // separated by , or ;
        const strPattern = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g;
        let m;
        let idx = 0;
        while ((m = strPattern.exec(tableContent)) !== null) {
            idx++;
            const raw = m[1] !== undefined ? m[1] : m[2];
            const decoded = decodeAllEscapes(raw);
            results.push({
                index: idx,
                raw: raw,
                decoded: decoded,
                hasEscapes: raw !== decoded
            });
        }
        log('EXTRACT', `Extracted ${results.length} strings from table`, 'OK');
    }

    // Also try to find standalone escaped strings anywhere
    if (results.length === 0) {
        log('EXTRACT', 'No table found, scanning for escaped strings globally', 'WARN');
        const globalStrPattern = /"((?:\\[\d]{1,3})+(?:[^"\\]|\\.)*)"/g;
        let m;
        let idx = 0;
        while ((m = globalStrPattern.exec(source)) !== null) {
            const raw = m[1];
            if (/\\\d{2,3}/.test(raw)) {
                idx++;
                const decoded = decodeAllEscapes(raw);
                results.push({ index: idx, raw, decoded, hasEscapes: true });
            }
        }
    }

    return results;
}

// ═══════════════════════════════════
//  Extract the shuffle/swap table
//  WeAreDevs shuffles the string indices
// ═══════════════════════════════════
function extractShuffleOps(source) {
    const ops = [];
    // Pattern: the for loop that swaps entries in r
    // for y,F in ipairs({{a,b},{c,d},{e,f}}) do while F[1]<F[2] do r[F[1]],r[F[2]],F[1],F[2]=r[F[2]],r[F[1]],F[1]+1,F[2]-1 end end
    const shuffleBlock = source.match(/for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{([\s\S]*?)\}\s*\)\s*do\s+while/);
    if (shuffleBlock) {
        const pairPattern = /\{\s*(-?\d+[^,]*),\s*(-?\d+[^}]*)\}/g;
        // Need to parse the arithmetic expressions
        const content = shuffleBlock[1];
        const pairPattern2 = /\{([^}]+)\}/g;
        let m;
        while ((m = pairPattern2.exec(content)) !== null) {
            const parts = m[1].split(',');
            if (parts.length === 2) {
                try {
                    const a = evalSimpleExpr(parts[0].trim());
                    const b = evalSimpleExpr(parts[1].trim());
                    if (a !== null && b !== null) {
                        ops.push([a, b]);
                    }
                } catch(e) {}
            }
        }
        log('SHUFFLE', `Found ${ops.length} shuffle operations`, 'OK');
    }
    return ops;
}

function evalSimpleExpr(expr) {
    // Evaluate simple arithmetic: 123+456, 123-456, -123+456, etc.
    expr = expr.replace(/\s/g, '');
    // Handle negative prefix
    try {
        // Only allow digits, +, -, *, (, )
        if (/^[\d+\-*()]+$/.test(expr)) {
            // Safe to eval simple math
            const result = Function('"use strict"; return (' + expr + ')')();
            if (typeof result === 'number' && isFinite(result)) {
                return Math.round(result);
            }
        }
    } catch(e) {}
    return null;
}

function applyShuffles(strings, ops) {
    // Clone the array (1-indexed in Lua, 0-indexed here)
    const arr = [...strings];
    for (const [startA, startB] of ops) {
        let a = startA; // Lua 1-indexed
        let b = startB;
        while (a < b) {
            const idxA = a - 1; // convert to 0-indexed
            const idxB = b - 1;
            if (idxA >= 0 && idxA < arr.length && idxB >= 0 && idxB < arr.length) {
                [arr[idxA], arr[idxB]] = [arr[idxB], arr[idxA]];
            }
            a++;
            b--;
        }
    }
    // Re-index
    return arr.map((s, i) => ({ ...s, index: i + 1 }));
}

// ═══════════════════════════════════
//  Find the accessor function y(n)
//  returns r[n - offset]
// ═══════════════════════════════════
function findAccessorOffset(source) {
    // Pattern: function y(y) return r[y-(-393492+446576)] end
    // or similar: return r[y-(expr)]
    const pattern = /function\s+\w+\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[\s*\w+\s*-\s*\(([^)]+)\)\s*\]/;
    const m = source.match(pattern);
    if (m) {
        const offset = evalSimpleExpr(m[1]);
        if (offset !== null) {
            log('ACCESSOR', `Found string accessor offset: ${offset}`, 'OK');
            return offset;
        }
    }
    // Try simpler pattern: return r[y+expr] or r[y-expr]
    const pattern2 = /function\s+\w+\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[\s*\w+\s*([+\-])\s*\(([^)]+)\)\s*\]/;
    const m2 = source.match(pattern2);
    if (m2) {
        const val = evalSimpleExpr(m2[2]);
        if (val !== null) {
            const offset = m2[1] === '-' ? val : -val;
            log('ACCESSOR', `Found string accessor offset: ${offset}`, 'OK');
            return offset;
        }
    }
    return null;
}

// ═══════════════════════════════════
//  Resolve y(expr) calls to actual strings
// ═══════════════════════════════════
function resolveAccessorCalls(source, strings, offset) {
    if (offset === null || strings.length === 0) return {};
    const map = {};
    // Find all y(expr) calls
    // The accessor function name - find it
    const fnNameMatch = source.match(/local\s+function\s+(\w+)\s*\(\s*\w+\s*\)\s*return\s+\w+\s*\[/);
    const fnName = fnNameMatch ? fnNameMatch[1] : null;
    if (!fnName) return map;

    const callPattern = new RegExp(fnName + '\\s*\\(([^)]+)\\)', 'g');
    let m;
    while ((m = callPattern.exec(source)) !== null) {
        const argExpr = m[1].trim();
        const argVal = evalSimpleExpr(argExpr);
        if (argVal !== null) {
            const idx = argVal - offset; // 1-indexed
            if (idx >= 1 && idx <= strings.length) {
                const str = strings[idx - 1];
                map[m[0]] = str.decoded;
            }
        }
    }
    log('RESOLVE', `Resolved ${Object.keys(map).length} string accessor calls`, 'OK');
    return map;
}

// ═══════════════════════════════════
//  Detect VM patterns
// ═══════════════════════════════════
function detectVMPatterns(source) {
    const patterns = [];

    const checks = [
        { re: /return\s*\(\s*function\s*\(\.\.\.\)/, name: 'Self-executing wrapper', severity: 'high' },
        { re: /local\s+\w\s*=\s*\{[\s\S]*?\\(\d{3})/,  name: 'Escaped string table', severity: 'high' },
        { re: /for\s+\w+\s*,\s*\w+\s+in\s+ipairs[\s\S]*?while\s+\w+\[/, name: 'Index shuffle loop', severity: 'high' },
        { re: /getfenv\s*(\(\s*\)|\s+and)/, name: 'getfenv usage', severity: 'med' },
        { re: /unpack\s+or\s+table/, name: 'unpack compatibility', severity: 'low' },
        { re: /newproxy/, name: 'newproxy (VM coroutine)', severity: 'med' },
        { re: /setmetatable\s*\(\s*\{/, name: 'Metatable VM dispatch', severity: 'high' },
        { re: /while\s+\w+\s+do\s+if\s+\w+\s*</, name: 'VM dispatcher loop', severity: 'high' },
        { re: /select\s*\(\s*["']#/, name: 'Vararg count', severity: 'low' },
        { re: /loadstring\s+or\s+load/, name: 'Dynamic code loading', severity: 'high' },
        { re: /string\.char/, name: 'string.char usage', severity: 'low' },
        { re: /string\.byte/, name: 'string.byte usage', severity: 'low' },
        { re: /string\.sub/, name: 'string.sub usage', severity: 'low' },
        { re: /math\.floor/, name: 'math.floor usage', severity: 'low' },
        { re: /bit32/, name: 'Bitwise operations', severity: 'med' },
        { re: /\w+\s*=\s*\w+\s*\+\s*\(\s*-?\d+[+-]\d+\s*\)/, name: 'Obfuscated arithmetic', severity: 'med' },
        { re: /wearedevs/i, name: 'WeAreDevs signature', severity: 'info' },
        { re: /v\d+\.\d+\.\d+/, name: 'Version string', severity: 'info' },
    ];

    for (const c of checks) {
        const matches = source.match(new RegExp(c.re.source, 'g'));
        if (matches) {
            patterns.push({ ...c, count: matches.length });
        }
    }

    return patterns;
}

// ═══════════════════════════════════
//  Extract function calls & structure
// ═══════════════════════════════════
function extractStructure(source) {
    const funcs = [];
    const locals = [];
    const tables = [];

    // Functions
    const fnRe = /(?:local\s+)?function\s+(\w+)\s*\(([^)]*)\)/g;
    let m;
    while ((m = fnRe.exec(source)) !== null) {
        funcs.push({ name: m[1], params: m[2], pos: m.index });
    }

    // Local assignments
    const locRe = /local\s+(\w+)\s*=\s*([^\n;]{1,100})/g;
    while ((m = locRe.exec(source)) !== null) {
        locals.push({
            name: m[1],
            value: m[2].trim(),
            obf: /^[_lIoO01]{3,}$/.test(m[1]) || /^_0x/.test(m[1])
        });
    }

    // Tables
    const tblRe = /(?:local\s+)?(\w)\s*=\s*\{/g;
    while ((m = tblRe.exec(source)) !== null) {
        tables.push({ name: m[1], pos: m.index });
    }

    return { funcs, locals, tables };
}

// ═══════════════════════════════════
//  Build the deobfuscated output
// ═══════════════════════════════════
function buildDeobfuscatedOutput(source, strings, accessorMap) {
    let output = source;

    // Replace accessor calls with actual strings
    // Sort by length descending to avoid partial replacements
    const entries = Object.entries(accessorMap).sort((a, b) => b[0].length - a[0].length);
    for (const [call, str] of entries) {
        // Escape regex special chars in the call
        const escaped = call.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        output = output.replace(new RegExp(escaped, 'g'), JSON.stringify(str));
    }

    // Also decode any remaining escaped strings in the source
    output = output.replace(/"((?:[^"\\]|\\.)*\\[\d]{2,3}(?:[^"\\]|\\.)*)"/g, (match, inner) => {
        const decoded = decodeAllEscapes(inner);
        if (decoded !== inner) {
            return JSON.stringify(decoded);
        }
        return match;
    });

    return output;
}

// ═══════════════════════════════════
//  MAIN: Deobfuscate
// ═══════════════════════════════════
function deobfuscate() {
    const source = document.getElementById('codeIn').value.trim();
    if (!source) return alert('Paste some code first!');

    // Reset
    G.logs = [];
    G.strings = [];
    G.decoded = [];
    G.structure = { funcs:[], locals:[], tables:[], meta:[], envCalls:[] };
    G.stats = { obfScore:0, strCount:0, decCount:0, funcs:0, tables:0, patterns:0, methods: new Set() };
    G.output = '';

    prog(5);

    setTimeout(() => {
        try {
            runAnalysis(source);
        } catch(e) {
            log('ERROR', 'Analysis failed: ' + e.message, 'ERR');
            console.error(e);
        }
        renderAll();
        prog(100);
        setTimeout(() => prog(0), 1500);
    }, 30);
}

function runAnalysis(source) {
    log('INIT', '══════════════════════════════════════');
    log('INIT', ' Luau VM Deobfuscator');
    log('INIT', `Input: ${source.length} bytes, ${source.split('\n').length} lines`);
    log('INIT', '══════════════════════════════════════');

    prog(10);

    // ── Step 1: Detect obfuscator ──
    log('PHASE', '▶ Step 1: Detect obfuscator type');
    const vmPatterns = detectVMPatterns(source);
    G.stats.patterns = vmPatterns.length;

    if (source.includes('wearedevs') || source.includes('WeAreDevs')) {
        log('DETECT', '✓ WeAreDevs obfuscator identified', 'OK');
        G.stats.methods.add('WeAreDevs VM');
    }

    for (const p of vmPatterns) {
        const icon = p.severity === 'high' ? '🔴' : p.severity === 'med' ? '🟡' : p.severity === 'info' ? 'ℹ️' : '🟢';
        log('PATTERN', `${icon} ${p.name} (×${p.count})`, p.severity === 'high' ? 'WARN' : 'INFO');
    }

    // Calculate obfuscation score
    let score = 0;
    for (const p of vmPatterns) {
        score += p.severity === 'high' ? 15 : p.severity === 'med' ? 8 : 3;
    }
    G.stats.obfScore = Math.min(100, score);

    prog(25);

    // ── Step 2: Extract string table ──
    log('PHASE', '▶ Step 2: Extract string table');
    const rawStrings = extractStringTable(source);
    G.stats.strCount = rawStrings.length;

    for (const s of rawStrings) {
        if (s.hasEscapes) {
            G.stats.decCount++;
            G.stats.methods.add('Decimal Escapes');
        }
    }

    prog(40);

    // ── Step 3: Apply index shuffles ──
    log('PHASE', '▶ Step 3: Resolve index shuffles');
    const shuffleOps = extractShuffleOps(source);
    let finalStrings;
    if (shuffleOps.length > 0) {
        finalStrings = applyShuffles(rawStrings, shuffleOps);
        G.stats.methods.add('Index Shuffle');
        log('SHUFFLE', `Applied ${shuffleOps.length} shuffle ops to ${rawStrings.length} strings`, 'OK');
    } else {
        finalStrings = rawStrings;
        log('SHUFFLE', 'No shuffle operations found', 'INFO');
    }

    G.strings = finalStrings;

    prog(55);

    // ── Step 4: Find accessor offset ──
    log('PHASE', '▶ Step 4: Resolve string accessor');
    const offset = findAccessorOffset(source);
    let accessorMap = {};
    if (offset !== null) {
        accessorMap = resolveAccessorCalls(source, finalStrings, offset);
    } else {
        log('ACCESSOR', 'Could not find accessor offset — strings shown by index', 'WARN');
    }

    prog(70);

    // ── Step 5: Structure analysis ──
    log('PHASE', '▶ Step 5: Structure analysis');
    const struct = extractStructure(source);
    G.structure = struct;
    G.stats.funcs = struct.funcs.length;
    G.stats.tables = struct.tables.length;
    log('STRUCT', `Found ${struct.funcs.length} functions, ${struct.locals.length} locals, ${struct.tables.length} tables`, 'OK');

    prog(85);

    // ── Step 6: Build output ──
    log('PHASE', '▶ Step 6: Build deobfuscated output');
    G.output = buildDeobfuscatedOutput(source, finalStrings, accessorMap);

    // ── Summary ──
    log('DONE', '══════════════════════════════════════');
    log('DONE', ` Strings extracted: ${G.stats.strCount}`);
    log('DONE', ` Strings decoded:   ${G.stats.decCount}`);
    log('DONE', ` Functions:         ${G.stats.funcs}`);
    log('DONE', ` Obfuscation:       ${G.stats.obfScore}/100`);
    log('DONE', ` Methods: ${[...G.stats.methods].join(', ') || 'None'}`);
    log('DONE', '══════════════════════════════════════');

    prog(95);
}

// ═══════════════════════════════════
//  RENDERERS
// ═══════════════════════════════════
function renderAll() {
    renderOverview();
    renderStrings();
    renderStructure();
    renderLog();
    renderDecoded();
    document.getElementById('outInfo').textContent = `${G.strings.length} strings | ${G.logs.length} logs`;
}

function renderOverview() {
    document.getElementById('emptyState').style.display = 'none';
    const el = document.getElementById('overviewOut');
    el.style.display = 'block';

    const obfColor = G.stats.obfScore >= 70 ? 'var(--red)' : G.stats.obfScore >= 40 ? 'var(--orange)' : G.stats.obfScore >= 15 ? 'var(--accent)' : 'var(--green)';
    const obfLabel = G.stats.obfScore >= 70 ? 'Heavy VM' : G.stats.obfScore >= 40 ? 'Moderate' : G.stats.obfScore >= 15 ? 'Light' : 'Minimal';

    el.innerHTML = `
        <div class="out-area">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Obfuscation</div>
                    <div class="stat-val" style="color:${obfColor}">${G.stats.obfScore}/100</div>
                    <div class="stat-sub">${obfLabel}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Strings</div>
                    <div class="stat-val" style="color:var(--green)">${G.stats.strCount}</div>
                    <div class="stat-sub">${G.stats.decCount} decoded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Functions</div>
                    <div class="stat-val" style="color:var(--accent)">${G.stats.funcs}</div>
                    <div class="stat-sub">${G.stats.tables} tables</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Patterns</div>
                    <div class="stat-val" style="color:var(--purple)">${G.stats.patterns}</div>
                    <div class="stat-sub">VM signatures</div>
                </div>
            </div>
            ${G.stats.methods.size > 0 ? `
            <div class="section" style="margin-top:12px">
                <div class="section-head"><span class="dot dot-o"></span>Encoding Methods</div>
                <div class="section-body">
                    ${[...G.stats.methods].map(m => `<span class="str-method" style="margin:2px">${esc(m)}</span>`).join(' ')}
                </div>
            </div>` : ''}
            <div class="section" style="margin-top:12px">
                <div class="section-head"><span class="dot dot-b"></span>Decoded Strings (first 30)</div>
                <div class="section-body">
                    ${G.strings.slice(0,30).map(s => `
                        <div class="str-row">
                            <span class="str-idx">${s.index}</span>
                            <span class="str-dec">${esc(trunc(s.decoded, 100))}</span>
                        </div>
                    `).join('') || '<span style="color:var(--dim)">No strings extracted</span>'}
                </div>
            </div>
        </div>
    `;
}

function renderStrings() {
    const el = document.getElementById('stringsOut');
    if (G.strings.length === 0) {
        el.innerHTML = '<div class="empty"><div class="ico">🔤</div><div>No strings found</div></div>';
        return;
    }

    let html = '';
    for (const s of G.strings) {
        html += `<div class="str-row" data-filter="${esc((s.decoded+s.raw).toLowerCase())}">
            <span class="str-idx">${s.index}</span>
            ${s.hasEscapes ? '<span class="str-method">decoded</span>' : '<span class="str-method" style="background:rgba(107,122,141,0.12);color:var(--dim)">raw</span>'}
            <span class="str-raw" title="Raw">${esc(trunc(s.raw, 50))}</span>
            <span style="color:var(--dim)">→</span>
            <span class="str-dec" title="Decoded">${esc(trunc(s.decoded, 60))}</span>
        </div>`;
    }
    el.innerHTML = html;
}

function renderStructure() {
    const el = document.getElementById('structOut');
    let html = '';

    if (G.structure.funcs && G.structure.funcs.length > 0) {
        html += '<div class="section"><div class="section-head"><span class="dot dot-b"></span>Functions ('+G.structure.funcs.length+')</div><div class="section-body">';
        for (const f of G.structure.funcs) {
            html += `<div style="padding:2px 0;font-size:0.82em"><span style="color:var(--yellow)">${esc(f.name)}</span><span style="color:var(--dim)">(${esc(f.params)})</span></div>`;
        }
        html += '</div></div>';
    }

    if (G.structure.locals && G.structure.locals.length > 0) {
        const obfLocals = G.structure.locals.filter(l => l.obf);
        html += '<div class="section"><div class="section-head"><span class="dot dot-o"></span>Locals ('+G.structure.locals.length+', '+obfLocals.length+' obfuscated)</div><div class="section-body">';
        for (const l of G.structure.locals.slice(0, 40)) {
            html += `<div style="padding:2px 0;font-size:0.82em">
                <span style="color:${l.obf ? 'var(--orange)' : 'var(--accent)'}">${esc(l.name)}</span>
                <span style="color:var(--dim)"> = ${esc(trunc(l.value, 70))}</span>
            </div>`;
        }
        if (G.structure.locals.length > 40) html += `<div style="color:var(--dim);font-size:0.78em">...+${G.structure.locals.length-40} more</div>`;
        html += '</div></div>';
    }

    if (!html) html = '<div class="empty"><div class="ico">🌳</div><div>No structure data</div></div>';
    el.innerHTML = html;
}

function renderLog() {
    const el = document.getElementById('logOut');
    let html = '';
    for (const l of G.logs) {
        const cls = l.level === 'OK' ? 't-ok' : l.level === 'WARN' ? 't-warn' : l.level === 'ERR' ? 't-err' : 't-info';
        html += `<div class="log-line" data-filter="${esc((l.cat+' '+l.msg).toLowerCase())}">
            <span class="log-tag ${cls}">${esc(l.cat.slice(0,8))}</span>
            <span>${esc(l.msg)}</span>
        </div>`;
    }
    el.innerHTML = html || '<div class="empty"><div class="ico">📋</div></div>';
}

function renderDecoded() {
    const el = document.getElementById('decodedOut');
    if (!G.output) {
        el.innerHTML = '<div class="empty"><div class="ico">✨</div><div>No output yet</div></div>';
        return;
    }

    // Show the string table as the primary useful output
    let stringTableOutput = '-- ═══════════════════════════════════\n';
    stringTableOutput += '-- DECODED STRING TABLE\n';
    stringTableOutput += '-- ═══════════════════════════════════\n\n';

    for (const s of G.strings) {
        const safe = s.decoded.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
        stringTableOutput += `-- [${s.index}] = "${safe}"\n`;
    }

    stringTableOutput += '\n-- ═══════════════════════════════════\n';
    stringTableOutput += '-- FULL SOURCE (with resolved strings)\n';
    stringTableOutput += '-- ═══════════════════════════════════\n\n';
    stringTableOutput += G.output;

    el.innerHTML = `
        <div style="padding:8px 12px;display:flex;gap:6px;border-bottom:1px solid var(--border);">
            <button class="copy-btn" onclick="copyOutput()">📋 Copy All</button>
            <button class="copy-btn" onclick="copyStrings()">📋 Copy Strings Only</button>
            <span style="font-size:0.72em;color:var(--dim);display:flex;align-items:center">${G.strings.length} strings decoded</span>
        </div>
        <div class="code-block" style="margin:0;border:none;border-radius:0;max-height:calc(100vh - 150px);overflow:auto">${highlightLua(stringTableOutput)}</div>
    `;
}

function highlightLua(code) {
    let html = esc(code);
    // Comments
    html = html.replace(/(--[^\n]*)/g, '<span class="hl-cmt">$1</span>');
    // Strings
    html = html.replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)/g, '<span class="hl-str">$1</span>');
    // Numbers
    html = html.replace(/\b(\d+(?:\.\d+)?)\b/g, '<span class="hl-num">$1</span>');
    // Keywords
    const kws = ['local','function','return','end','if','then','else','elseif','for','while','do','repeat','until','break','in','or','and','not','true','false','nil'];
    for (const kw of kws) {
        html = html.replace(new RegExp('\\b(' + kw + ')\\b', 'g'), '<span class="hl-kw">$1</span>');
    }
    return html;
}

// ═══════════════════════════════════
//  UI actions
// ═══════════════════════════════════
function filterStrRows() {
    const q = document.getElementById('strFilter').value.toLowerCase();
    document.querySelectorAll('#stringsOut .str-row').forEach(r => {
        r.style.display = (r.dataset.filter || '').includes(q) ? '' : 'none';
    });
}

function filterLogRows() {
    const q = document.getElementById('logFilter').value.toLowerCase();
    document.querySelectorAll('#logOut .log-line').forEach(r => {
        r.style.display = (r.dataset.filter || '').includes(q) ? '' : 'none';
    });
}

function copyOutput() {
    let text = '';
    for (const s of G.strings) {
        text += `[${s.index}] = "${s.decoded}"\n`;
    }
    text += '\n' + G.output;
    navigator.clipboard.writeText(text);
    showCopyFeedback();
}

function copyStrings() {
    let text = '';
    for (const s of G.strings) {
        text += `[${s.index}] ${s.decoded}\n`;
    }
    navigator.clipboard.writeText(text);
    showCopyFeedback();
}

function showCopyFeedback() {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = '✅ Copied!';
    btn.style.borderColor = 'var(--green)';
    btn.style.color = 'var(--green)';
    setTimeout(() => { btn.textContent = orig; btn.style.borderColor = ''; btn.style.color = ''; }, 1200);
}

function clearAll() {
    document.getElementById('codeIn').value = '';
    G.logs = []; G.strings = []; G.output = '';
    document.getElementById('emptyState').style.display = '';
    document.getElementById('overviewOut').style.display = 'none';
    document.getElementById('stringsOut').innerHTML = '';
    document.getElementById('structOut').innerHTML = '';
    document.getElementById('logOut').innerHTML = '';
    document.getElementById('decodedOut').innerHTML = '';
    document.getElementById('outInfo').textContent = '—';
    updateSize();
}

function exportAll() {
    if (G.strings.length === 0 && G.logs.length === 0) return alert('Nothing to export');
    let text = '=== Luau Deobfuscation Report ===\n\n';
    text += '== DECODED STRINGS ==\n';
    for (const s of G.strings) text += `[${s.index}] ${s.decoded}\n`;
    text += '\n== LOG ==\n';
    for (const l of G.logs) text += `[${l.level}][${l.cat}] ${l.msg}\n`;
    text += '\n== DEOBFUSCATED SOURCE ==\n';
    text += G.output || '(none)';

    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'deobf_report.txt';
    a.click();
    URL.revokeObjectURL(a.href);
}

function loadSample() {
    document.getElementById('codeIn').value = `--[[ v1.0.0 https://wearedevs.net/obfuscator ]] return(function(...)local r={"\\073\\074\\051\\087\\115\\074\\078\\061","\\083\\107\\113\\047\\068\\108\\061\\061";"\\104\\086\\088\\119\\081\\057\\055\\052";"\\085\\080\\073\\107\\115\\078\\055\\111\\100\\074\\088\\119\\078\\107\\107\\078\\081\\054\\118\\061";"\\098\\049\\106\\061";"\\078\\113\\065\\080\\107\\078\\047\\080\\068\\074\\049\\107\\100\\097\\051\\090";"\\100\\054\\070\\106\\066\\120\\070\\066\\100\\107\\073\\070\\073\\122\\109\\056\\088\\103\\061\\061";"\\115\\097\\102\\061";"\\081\\083\\070\\120\\088\\116\\079\\057\\083\\054\\047\\101\\100\\113\\107\\049\\073\\074\\118\\061";"\\104\\067\\107\\054\\115\\057\\107\\054\\072\\080\\088\\110\\072\\101\\047\\070";"\\072\\052\\070\\054\\068\\118\\061\\061","\\088\\054\\049\\078\\078\\067\\065\\053\\072\\054\\076\\086\\115\\051\\110\\068\\118\\108\\061\\061","\\083\\078\\105\\070\\115\\120\\107\\114\\115\\054\\102\\116\\100\\077\\068\\100\\115\\118\\061\\061";"\\057\\102\\088\\101\\057\\051\\121\\052\\068\\067\\051\\069\\118\\122\\049\\079","\\068\\067\\116\\110\\073\\074\\049\\106";"\\078\\107\\056\\076\\068\\074\\049\\116\\104\\051\\109\\097\\099\\078\\068\\100","\\057\\078\\055\\072\\078\\078\\072\\086\\068\\078\\105\\068\\072\\078\\100\\116\\066\\113\\071\\047";"\\068\\080\\121\\119\\115\\086\\056\\061","\\083\\067\\110\\049\\078\\113\\088\\081\\072\\054\\111\\061";"\\068\\086\\049\\116\\072\\108\\061\\061","\\085\\087\\108\\070\\068\\117\\106\\079\\085\\108\\061\\061";"\\068\\101\\047\\089\\115\\086\\056\\061";"\\115\\097\\056\\061","\\085\\108\\061\\061";"\\080\\116\\105\\079\\115\\101\\088\\070\\099\\103\\061\\061";"\\081\\122\\070\\066\\118\\080\\110\\122\\066\\078\\072\\086\\068\\107\\102\\119";}end)()`;
    updateSize();
}

updateSize();
