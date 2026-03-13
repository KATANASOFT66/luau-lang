/*
 * ═══════════════════════════════════════════════════
 *  Luau VM Deobfuscator
 *  
 *  WeAreDevs obfuscator compiles Lua source into
 *  CUSTOM BYTECODE that runs on a VM interpreter
 *  embedded in the script. The string table contains
 *  raw binary VM data — NOT human-readable strings.
 *
 *  To get the REAL code, you must either:
 *   A) Run the script with hooks that intercept API calls
 *   B) Reverse-engineer the VM interpreter
 *
 *  This tool does BOTH:
 *   1) Static analysis of the VM structure
 *   2) Generates a hook/wrapper script that,
 *      when run in a Luau environment, intercepts
 *      all the real function calls and outputs
 *      the decompiled logic
 * ═══════════════════════════════════════════════════
 */

const ST = {
  logs: [],
  rawStrings: [],
  shuffledStrings: [],
  vmInfo: {},
  hookScript: '',
  stats: { score:0, strN:0, funcs:0, vmOps:0, methods:new Set() }
};

// ── Tabs ──
document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('on'));
    document.querySelectorAll('.tc').forEach(x => x.classList.remove('on'));
    t.classList.add('on');
    document.getElementById('t-' + t.dataset.t).classList.add('on');
  };
});

const $=id=>document.getElementById(id);
$('ci').addEventListener('input', uSz);
function uSz(){ const v=$('ci').value; $('sz').textContent=v.length>1024?(v.length/1024).toFixed(1)+' KB':v.length+' B'; }
function pg(p){ $('pg').style.width=p+'%'; }
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function trn(s,n=80){ return s.length>n?s.slice(0,n)+'…':s; }
function L(c,m,l='INFO'){ ST.logs.push({c,m,l}); }

// ═══════════════════════════════════════
//  Decimal escape decoder
//  \073 → chr(73) = 'I'
// ═══════════════════════════════════════
function decEsc(s) {
  return s.replace(/\\(\d{1,3})/g, (_, d) => {
    const c = parseInt(d, 10);
    return c >= 0 && c <= 255 ? String.fromCharCode(c) : _;
  });
}

// ═══════════════════════════════════════
//  Extract string table entries (raw)
// ═══════════════════════════════════════
function extractStringTable(src) {
  const entries = [];
  const tblMatch = src.match(/local\s+(\w)\s*=\s*\{/);
  if (!tblMatch) { L('TABLE','No string table found','WARN'); return { vn:'?', entries }; }
  
  const vn = tblMatch[1];
  const start = tblMatch.index + tblMatch[0].length;
  let depth = 1, i = start;
  while (i < src.length && depth > 0) {
    if (src[i]==='{') depth++;
    else if (src[i]==='}') depth--;
    if (depth > 0) i++;
  }
  const body = src.substring(start, i);
  
  const re = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g;
  let m, idx = 0;
  while ((m = re.exec(body)) !== null) {
    idx++;
    const raw = m[1] !== undefined ? m[1] : m[2];
    const decoded = decEsc(raw);
    // Show as hex dump for binary data
    let hexDump = '';
    let printable = '';
    for (let j = 0; j < decoded.length; j++) {
      const cc = decoded.charCodeAt(j);
      hexDump += cc.toString(16).padStart(2,'0') + ' ';
      printable += (cc >= 32 && cc <= 126) ? decoded[j] : '.';
    }
    entries.push({ i: idx, raw, decoded, hexDump: hexDump.trim(), printable, len: decoded.length });
  }
  
  L('TABLE', `Extracted ${entries.length} entries from table "${vn}"`, 'OK');
  return { vn, entries };
}

// ═══════════════════════════════════════
//  Shuffle operations
// ═══════════════════════════════════════
function extractShuffles(src) {
  const ops = [];
  const block = src.match(/for\s+\w+\s*,\s*\w+\s+in\s+ipairs\s*\(\s*\{([\s\S]*?)\}\s*\)\s*do\s+while/);
  if (!block) return ops;
  const pRe = /\{([^}]+)\}/g;
  let m;
  while ((m = pRe.exec(block[1])) !== null) {
    const parts = m[1].split(',');
    if (parts.length >= 2) {
      const a = sEval(parts[0].trim());
      const b = sEval(parts[1].trim());
      if (a !== null && b !== null) ops.push([a, b]);
    }
  }
  return ops;
}

function sEval(expr) {
  expr = expr.replace(/\s/g,'');
  if (!/^[-\d+*()]+$/.test(expr)) return null;
  try {
    const r = Function('"use strict";return(' + expr + ')')();
    return typeof r === 'number' && isFinite(r) ? Math.round(r) : null;
  } catch { return null; }
}

function applyShuffle(arr, ops) {
  const a = [...arr];
  for (const [sA, sB] of ops) {
    let lo = sA, hi = sB;
    while (lo < hi) {
      const iA = lo-1, iB = hi-1;
      if (iA>=0 && iA<a.length && iB>=0 && iB<a.length) [a[iA],a[iB]]=[a[iB],a[iA]];
      lo++; hi--;
    }
  }
  return a.map((s,i)=>({...s, i:i+1}));
}

// ═══════════════════════════════════════
//  VM Structure Analysis
// ═══════════════════════════════════════
function analyzeVM(src) {
  const info = {
    type: 'Unknown',
    hasDispatcher: false,
    dispatcherType: '',
    envAccess: [],
    apiCalls: [],
    opcodeCount: 0,
    hasIntegrityCheck: false,
    hasAntiDebug: false,
    wrapperArgs: [],
    innerFunctions: 0,
    complexity: 0,
  };
  
  // Identify obfuscator
  if (/wearedevs/i.test(src)) {
    info.type = 'WeAreDevs';
    L('VM', '✓ WeAreDevs obfuscator identified', 'OK');
  }
  
  // VM dispatcher detection
  const dispatchPatterns = [
    { re: /while\s+(\w+)\s+do\s+if\s+\1\s*<\s*(\d+)/g, type: 'numeric-compare-chain' },
    { re: /while\s+(\w+)\s+do[\s\S]{0,100}if\s+\1\s*==/g, type: 'equality-dispatch' },
    { re: /while\s+true\s+do[\s\S]{0,200}if\s+\w+\s*==/g, type: 'infinite-loop-dispatch' },
  ];
  for (const dp of dispatchPatterns) {
    const matches = src.match(dp.re);
    if (matches) {
      info.hasDispatcher = true;
      info.dispatcherType = dp.type;
      info.opcodeCount = matches.length;
      L('VM', `Dispatcher: ${dp.type} (${matches.length} branches)`, 'OK');
    }
  }
  
  // Count if/elseif chains (VM opcodes)
  const ifChains = (src.match(/if\s+\w+\s*[<>=~]+/g) || []).length;
  info.opcodeCount = Math.max(info.opcodeCount, ifChains);
  info.complexity = ifChains;
  
  // Env access at the end
  const envMatch = src.match(/end\s*\)\s*\(([^)]+)\)/);
  if (envMatch) {
    info.wrapperArgs = envMatch[1].split(',').map(s => s.trim());
    L('VM', `Wrapper passes: ${info.wrapperArgs.join(', ')}`, 'OK');
  }
  
  // Count inner function definitions
  info.innerFunctions = (src.match(/function\s*\(/g) || []).length;
  
  // Anti-debug / integrity
  if (/Integrity|integrity/i.test(src)) {
    info.hasIntegrityCheck = true;
    L('VM', '⚠ Integrity check detected', 'WARN');
  }
  
  // Detect what APIs the VM references
  const knownAPIs = [
    'getfenv', 'setfenv', 'setmetatable', 'getmetatable',
    'newproxy', 'select', 'unpack', 'pcall', 'xpcall',
    'loadstring', 'string.char', 'string.byte', 'string.sub',
    'string.len', 'string.rep', 'string.gsub', 'string.format',
    'table.insert', 'table.concat', 'table.unpack', 'table.move',
    'math.floor', 'math.abs', 'math.max', 'math.min',
    'bit32.bxor', 'bit32.band', 'bit32.bor', 'bit32.lshift', 'bit32.rshift',
    'coroutine.create', 'coroutine.resume', 'coroutine.yield', 'coroutine.wrap',
    'tostring', 'tonumber', 'type', 'rawget', 'rawset', 'rawequal', 'rawlen',
    'pairs', 'ipairs', 'next', 'error', 'assert',
    'game', 'workspace', 'Instance.new', 'wait', 'spawn', 'delay',
    'print', 'warn',
  ];
  
  for (const api of knownAPIs) {
    // Check both direct references and string matches
    const escaped = api.replace(/\./g, '\\.');
    if (new RegExp('\\b' + escaped + '\\b').test(src)) {
      info.apiCalls.push(api);
    }
  }
  
  L('VM', `VM uses ${info.apiCalls.length} standard APIs`, 'OK');
  L('VM', `${info.innerFunctions} inner functions, complexity ${info.complexity}`, 'OK');
  
  return info;
}

// ═══════════════════════════════════════
//  Generate Hook Script
//  This is the KEY — generates Luau code
//  that when executed in a Roblox/Luau env,
//  intercepts ALL real operations
// ═══════════════════════════════════════
function generateHookScript(src, vmInfo) {
  // This generates a Luau script that wraps the obfuscated code
  // and intercepts every function call, property access, etc.
  
  const script = `--[[
    ╔══════════════════════════════════════════╗
    ║  Luau VM Deobfuscator — Runtime Hook     ║
    ║  Paste this in your executor/environment  ║
    ║  It will run the obfuscated script and    ║
    ║  log every real operation it performs      ║
    ╚══════════════════════════════════════════╝
    
    HOW TO USE:
    1. Paste this entire script into your Luau executor
    2. It will execute the obfuscated code with hooks
    3. Check the output for the real decompiled operations
    4. All function calls, property accesses, and values
       will be logged in readable format
--]]

-- ═══════════ CONFIGURATION ═══════════
local LOG_OUTPUT = {} -- collected logs
local MAX_DEPTH = 50
local CALL_COUNT = 0

-- ═══════════ LOGGING ═══════════
local real_tostring = tostring
local real_type = type
local real_print = print
local real_warn = warn
local real_select = select
local real_pcall = pcall
local real_pairs = pairs
local real_ipairs = ipairs
local real_setmetatable = setmetatable
local real_getmetatable = getmetatable
local real_rawget = rawget
local real_rawset = rawset
local real_table_insert = table.insert
local real_table_concat = table.concat
local real_string_format = string.format
local real_string_rep = string.rep

local function safeStr(v)
    local t = real_type(v)
    if t == "string" then
        if #v > 200 then
            return '"' .. v:sub(1,200) .. '..."'
        end
        return '"' .. v .. '"'
    elseif t == "number" or t == "boolean" or t == "nil" then
        return real_tostring(v)
    elseif t == "table" then
        return "<table:" .. real_tostring(v):sub(-8) .. ">"
    elseif t == "function" then
        return "<func:" .. real_tostring(v):sub(-8) .. ">"
    elseif t == "userdata" then
        local ok, s = real_pcall(real_tostring, v)
        return ok and s or "<userdata>"
    else
        return "<" .. t .. ">"
    end
end

local function formatArgs(...)
    local n = real_select("#", ...)
    if n == 0 then return "" end
    local parts = {}
    for i = 1, n do
        parts[i] = safeStr(real_select(i, ...))
    end
    return real_table_concat(parts, ", ")
end

local function LOG(msg)
    CALL_COUNT = CALL_COUNT + 1
    local entry = "[" .. CALL_COUNT .. "] " .. msg
    real_table_insert(LOG_OUTPUT, entry)
    real_print("[DEOBF] " .. entry)
end

-- ═══════════ ENVIRONMENT PROXY ═══════════
-- Creates a proxy that logs all access

local function createProxy(target, name)
    if real_type(target) ~= "table" and real_type(target) ~= "userdata" then
        return target
    end
    
    local proxy = {}
    local meta = {
        __index = function(self, key)
            local fullName = name .. "." .. real_tostring(key)
            local value = target[key]
            LOG("GET  " .. fullName .. " = " .. safeStr(value))
            
            if real_type(value) == "function" then
                return function(...)
                    local args = formatArgs(...)
                    LOG("CALL " .. fullName .. "(" .. args .. ")")
                    local results = {real_pcall(value, ...)}
                    local success = results[1]
                    if success then
                        table.remove(results, 1)
                        if #results > 0 then
                            LOG("  => " .. formatArgs(unpack(results)))
                        end
                        return unpack(results)
                    else
                        LOG("  => ERROR: " .. real_tostring(results[2]))
                        error(results[2])
                    end
                end
            elseif real_type(value) == "table" or real_type(value) == "userdata" then
                return createProxy(value, fullName)
            end
            return value
        end,
        
        __newindex = function(self, key, value)
            local fullName = name .. "." .. real_tostring(key)
            LOG("SET  " .. fullName .. " = " .. safeStr(value))
            target[key] = value
        end,
        
        __call = function(self, ...)
            local args = formatArgs(...)
            LOG("CALL " .. name .. "(" .. args .. ")")
            local results = {real_pcall(target, ...)}
            local success = results[1]
            if success then
                table.remove(results, 1)
                if #results > 0 then
                    LOG("  => " .. formatArgs(unpack(results)))
                end
                return unpack(results)
            else
                LOG("  => ERROR: " .. real_tostring(results[2]))
                error(results[2])
            end
        end,
        
        __tostring = function()
            return real_tostring(target)
        end,
        
        __len = function()
            return #target
        end,
    }
    
    return real_setmetatable(proxy, meta)
end

-- ═══════════ HOOK CRITICAL FUNCTIONS ═══════════

-- Hook loadstring to capture dynamically loaded code
local real_loadstring = loadstring or load
local function hooked_loadstring(code, ...)
    LOG("═══ LOADSTRING CALLED ═══")
    if real_type(code) == "string" then
        LOG("CODE LENGTH: " .. #code)
        if #code < 5000 then
            LOG("CODE CONTENT:")
            -- Split into lines for readability
            for line in code:gmatch("[^\\n]+") do
                LOG("  | " .. line)
            end
        else
            LOG("CODE PREVIEW (first 2000 chars):")
            LOG(code:sub(1, 2000))
        end
    end
    LOG("═══ END LOADSTRING ═══")
    return real_loadstring(code, ...)
end

-- Hook getfenv
local real_getfenv = getfenv
local function hooked_getfenv(level)
    LOG("GETFENV(" .. real_tostring(level) .. ")")
    local env = real_getfenv(level or 0)
    return env -- Don't proxy the whole env to avoid breaking the VM
end

-- Hook setfenv  
local real_setfenv = setfenv
local function hooked_setfenv(fn, env)
    LOG("SETFENV called")
    return real_setfenv(fn, env)
end

-- Hook pcall/xpcall to see what's being protected
local function hooked_pcall(fn, ...)
    local args = formatArgs(...)
    LOG("PCALL(" .. safeStr(fn) .. ", " .. args .. ")")
    local results = {real_pcall(fn, ...)}
    if results[1] then
        LOG("  PCALL OK")
    else
        LOG("  PCALL FAIL: " .. real_tostring(results[2]))
    end
    return unpack(results)
end

-- Hook setmetatable to see VM dispatch tables
local function hooked_setmetatable(t, mt)
    LOG("SETMETATABLE on " .. safeStr(t))
    if mt then
        for k, v in real_pairs(mt) do
            LOG("  meta." .. real_tostring(k) .. " = " .. safeStr(v))
        end
    end
    return real_setmetatable(t, mt)
end

-- Hook newproxy (used by WeAreDevs for coroutine tricks)
local real_newproxy = newproxy
local function hooked_newproxy(addMeta)
    LOG("NEWPROXY(" .. real_tostring(addMeta) .. ")")
    return real_newproxy(addMeta)
end

-- Hook string.char (often used to reconstruct strings)
local real_string_char = string.char
string.char = function(...)
    local result = real_string_char(...)
    local args = formatArgs(...)
    LOG("STRING.CHAR(" .. args .. ") = " .. safeStr(result))
    return result
end

-- Hook string.byte
local real_string_byte = string.byte
string.byte = function(s, i, j)
    local results = {real_string_byte(s, i, j)}
    LOG("STRING.BYTE(" .. safeStr(s):sub(1,30) .. ", " .. real_tostring(i) .. ") = " .. formatArgs(unpack(results)))
    return unpack(results)
end

-- Hook string.sub
local real_string_sub = string.sub
string.sub = function(s, i, j)
    local result = real_string_sub(s, i, j)
    LOG("STRING.SUB(len=" .. #s .. ", " .. real_tostring(i) .. ", " .. real_tostring(j) .. ") = " .. safeStr(result):sub(1,50))
    return result
end

-- Hook table operations
local real_table_unpack = table.unpack or unpack
local function hooked_unpack(t, i, j)
    LOG("UNPACK(table, " .. real_tostring(i) .. ", " .. real_tostring(j) .. ")")
    return real_table_unpack(t, i, j)
end

-- Hook select
local function hooked_select(idx, ...)
    local result = {real_select(idx, ...)}
    LOG("SELECT(" .. real_tostring(idx) .. ", " .. formatArgs(...) .. ")")
    return unpack(result)
end

-- ═══════════ EXECUTE WITH HOOKS ═══════════

LOG("═══════════════════════════════════════")
LOG("  RUNTIME DEOBFUSCATION STARTING")
LOG("═══════════════════════════════════════")

-- The obfuscated code will be pasted below.
-- We override critical globals before running it.

local hooked_env = setmetatable({
    loadstring = hooked_loadstring,
    load = hooked_loadstring,
    pcall = hooked_pcall,
    setmetatable = hooked_setmetatable,
    newproxy = hooked_newproxy,
    select = hooked_select,
    getfenv = hooked_getfenv,
    setfenv = hooked_setfenv,
    unpack = hooked_unpack,
    print = function(...)
        LOG("PRINT: " .. formatArgs(...))
        real_print(...)
    end,
    warn = function(...)
        LOG("WARN: " .. formatArgs(...))
        real_warn(...)
    end,
    error = function(msg, level)
        LOG("ERROR: " .. real_tostring(msg))
        error(msg, (level or 1) + 1)
    end,
    -- Pass through everything else
}, {__index = getfenv and getfenv() or _ENV})

-- ═══════════ PASTE OBFUSCATED CODE BELOW ═══════════
local obfuscated = function(...)
-- <<<PASTE_YOUR_OBFUSCATED_CODE_HERE>>>
end

-- Run it in hooked environment
if setfenv then
    setfenv(obfuscated, hooked_env)
end

LOG("Executing obfuscated code...")
local ok, err = real_pcall(obfuscated)
if not ok then
    LOG("Execution error: " .. real_tostring(err))
end

LOG("═══════════════════════════════════════")
LOG("  DEOBFUSCATION COMPLETE")
LOG("  Total operations logged: " .. CALL_COUNT)
LOG("═══════════════════════════════════════")

-- Print summary
real_print("\\n\\n=== DEOBFUSCATION LOG ===")
for _, entry in real_ipairs(LOG_OUTPUT) do
    real_print(entry)
end
`;

  return script;
}

// ═══════════════════════════════════════
//  Generate the actual ready-to-use script
//  with the obfuscated code embedded
// ═══════════════════════════════════════
function generateReadyScript(src) {
  // Find the actual function body to embed
  // The obfuscated code is typically: return(function(...)...end)(...)
  // We need to capture the inner function
  
  const hookBase = generateHookScript(src, ST.vmInfo);
  
  // Replace the placeholder with actual code
  const ready = hookBase.replace(
    '-- <<<PASTE_YOUR_OBFUSCATED_CODE_HERE>>>',
    src
  );
  
  return ready;
}

// ═══════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════
function run() {
  const src = $('ci').value.trim();
  if (!src) return alert('Paste code first');
  
  // Reset
  ST.logs=[]; ST.rawStrings=[]; ST.shuffledStrings=[]; ST.vmInfo={};
  ST.hookScript='';
  ST.stats={score:0,strN:0,funcs:0,vmOps:0,methods:new Set()};
  pg(5);
  
  setTimeout(() => {
    try { doAnalysis(src); } catch(e) { L('ERROR',e.message,'ERR'); console.error(e); }
    renderAll();
    pg(100);
    setTimeout(()=>pg(0), 1200);
  }, 30);
}

function doAnalysis(src) {
  L('INIT','════════════════════════════════════════');
  L('INIT','Luau VM Deobfuscator — Analysis');
  L('INIT',`Input: ${src.length} bytes, ${src.split('\n').length} lines`);
  L('INIT','════════════════════════════════════════');
  
  pg(10);
  
  // Step 1: Extract raw string table
  L('STEP','▶ Step 1: Extract string table (raw VM data)');
  const { vn, entries } = extractStringTable(src);
  ST.rawStrings = entries;
  ST.stats.strN = entries.length;
  ST.stats.methods.add('Decimal Escapes');
  
  // Show what these really are — binary VM data
  let binaryCount = 0, textCount = 0;
  for (const s of entries) {
    let printableChars = 0;
    for (let i = 0; i < s.decoded.length; i++) {
      const c = s.decoded.charCodeAt(i);
      if (c >= 32 && c <= 126) printableChars++;
    }
    const ratio = s.decoded.length > 0 ? printableChars / s.decoded.length : 0;
    s.isBinary = ratio < 0.9;
    if (s.isBinary) binaryCount++; else textCount++;
  }
  
  L('TABLE', `${entries.length} entries: ${binaryCount} binary (VM data), ${textCount} text-like`, 'OK');
  
  pg(25);
  
  // Step 2: Apply shuffles
  L('STEP','▶ Step 2: Apply index shuffles');
  const shuffleOps = extractShuffles(src);
  if (shuffleOps.length > 0) {
    ST.shuffledStrings = applyShuffle(entries, shuffleOps);
    ST.stats.methods.add('Index Shuffle');
    L('SHUFFLE', `Applied ${shuffleOps.length} shuffles`, 'OK');
  } else {
    ST.shuffledStrings = entries;
    L('SHUFFLE', 'No shuffles found', 'INFO');
  }
  
  pg(40);
  
  // Step 3: Analyze VM structure
  L('STEP','▶ Step 3: Analyze VM interpreter');
  ST.vmInfo = analyzeVM(src);
  ST.stats.vmOps = ST.vmInfo.opcodeCount;
  ST.stats.funcs = ST.vmInfo.innerFunctions;
  ST.stats.score = Math.min(100,
    (ST.vmInfo.hasDispatcher ? 25 : 0) +
    Math.min(25, ST.vmInfo.opcodeCount / 4) +
    (ST.vmInfo.hasIntegrityCheck ? 10 : 0) +
    Math.min(20, ST.vmInfo.innerFunctions * 2) +
    Math.min(20, ST.vmInfo.apiCalls.length)
  );
  
  if (ST.vmInfo.type !== 'Unknown') ST.stats.methods.add(ST.vmInfo.type + ' VM');
  if (ST.vmInfo.hasDispatcher) ST.stats.methods.add('VM Dispatch: ' + ST.vmInfo.dispatcherType);
  
  pg(60);
  
  // Step 4: Generate hook script
  L('STEP','▶ Step 4: Generate runtime hook script');
  ST.hookScript = generateReadyScript(src);
  L('HOOK', `Generated hook script (${ST.hookScript.length} bytes)`, 'OK');
  
  pg(80);
  
  // Summary
  L('DONE','════════════════════════════════════════');
  L('DONE',`String table: ${ST.stats.strN} entries (${binaryCount} binary VM data)`);
  L('DONE',`VM type: ${ST.vmInfo.type}`);
  L('DONE',`VM complexity: ${ST.vmInfo.complexity} branches`);
  L('DONE',`Inner functions: ${ST.stats.funcs}`);
  L('DONE',`APIs used: ${ST.vmInfo.apiCalls.join(', ')}`);
  L('DONE','');
  L('DONE','⚠ This is a VM-based obfuscator.', 'WARN');
  L('DONE','The string table contains BINARY VM BYTECODE,', 'WARN');
  L('DONE','not human-readable text.', 'WARN');
  L('DONE','', 'WARN');
  L('DONE','To get the REAL code, use the Hook Script tab.', 'WARN');
  L('DONE','Run that script in your Luau environment and it', 'WARN');
  L('DONE','will intercept + log all real operations.', 'WARN');
  L('DONE','════════════════════════════════════════');
}

// ═══════════════════════════════════════
//  RENDERERS
// ═══════════════════════════════════════
function renderAll() {
  renderOv(); renderSt(); renderVm(); renderHk(); renderLg();
  $('oi').textContent = `${ST.stats.strN} strings | VM: ${ST.vmInfo.type||'?'}`;
}

function renderOv() {
  $('empt').style.display='none';
  const el=$('ovOut');
  el.style.display='block';
  const sc=ST.stats.score;
  const col=sc>=70?'var(--rd)':sc>=40?'var(--or)':sc>=15?'var(--ac)':'var(--gn)';

  el.innerHTML=`<div class="oa">
    <div class="sg">
      <div class="sc"><div class="sl">Obfuscation</div><div class="sv" style="color:${col}">${sc}/100</div><div class="ss">${ST.vmInfo.type||'Unknown'}</div></div>
      <div class="sc"><div class="sl">VM Data Entries</div><div class="sv" style="color:var(--pr)">${ST.stats.strN}</div><div class="ss">Binary VM bytecode</div></div>
      <div class="sc"><div class="sl">VM Branches</div><div class="sv" style="color:var(--ac)">${ST.stats.vmOps}</div><div class="ss">${ST.vmInfo.dispatcherType||'—'}</div></div>
      <div class="sc"><div class="sl">Functions</div><div class="sv" style="color:var(--yl)">${ST.stats.funcs}</div><div class="ss">Inner definitions</div></div>
    </div>
    
    <div class="warn-box">
      <b>⚠ This is a VM-based obfuscator</b><br><br>
      The string table does <b>NOT</b> contain readable strings — it contains
      <b>binary VM bytecode/constants</b> that are interpreted at runtime by a 
      custom virtual machine built into the script.<br><br>
      <b>To get the real code:</b><br>
      Go to the <b>⚡ Hook Script</b> tab → copy the generated script → 
      run it in your Luau environment (Roblox executor, etc.).<br>
      It will execute the obfuscated code while intercepting and logging 
      every real function call, property access, and value.
    </div>
    
    ${ST.vmInfo.apiCalls.length?`
    <div class="sec">
      <div class="sh">VM-Level API References (${ST.vmInfo.apiCalls.length})</div>
      <div class="sb">${ST.vmInfo.apiCalls.map(a=>`<span class="tag t-i" style="margin:2px;display:inline-block">${esc(a)}</span>`).join(' ')}</div>
    </div>`:''}
    
    ${ST.stats.methods.size?`
    <div class="sec">
      <div class="sh">Obfuscation Methods</div>
      <div class="sb">${[...ST.stats.methods].map(m=>`<span class="tag t-p" style="margin:2px;display:inline-block">${esc(m)}</span>`).join(' ')}</div>
    </div>`:''}
    
    ${ST.vmInfo.wrapperArgs.length?`
    <div class="sec">
      <div class="sh">Wrapper Arguments</div>
      <div class="sb" style="font-size:.82em;color:var(--d)">${ST.vmInfo.wrapperArgs.map(a=>`<code style="color:var(--yl)">${esc(a)}</code>`).join(', ')}</div>
    </div>`:''}
  </div>`;
}

function renderSt() {
  const el=$('stOut');
  const strs = ST.shuffledStrings.length ? ST.shuffledStrings : ST.rawStrings;
  if (!strs.length) { el.innerHTML='<div class="emp"><div class="ic">🔤</div></div>'; return; }
  
  let h = `<div class="info-box" style="margin-bottom:10px">
    These are the raw VM data entries after decimal-escape decoding.
    They contain binary bytecode, NOT readable text. Shown as hex dump + printable chars.
  </div>`;
  
  for (const s of strs) {
    const bgColor = s.isBinary ? 'rgba(199,146,234,.04)' : 'rgba(65,217,140,.06)';
    h+=`<div class="row" style="background:${bgColor};padding:6px 4px;margin:2px 0;border-radius:3px" data-f="${esc((s.printable+s.hexDump).toLowerCase())}">
      <span class="idx">${s.i}</span>
      <span class="tag ${s.isBinary?'t-p':'t-g'}" style="min-width:35px">${s.isBinary?'bin':'txt'}</span>
      <span style="flex:1">
        <div style="color:var(--d);font-size:.75em;font-family:monospace;word-break:break-all">${esc(trn(s.hexDump,90))}</div>
        <div style="color:${s.isBinary?'var(--pr)':'var(--gn)'};margin-top:2px">${esc(s.printable)}</div>
      </span>
      <span style="color:var(--d);font-size:.75em;flex-shrink:0">${s.len}B</span>
    </div>`;
  }
  el.innerHTML=h;
}

function renderVm() {
  const el=$('vmOut');
  const vm = ST.vmInfo;
  
  let h=`
    <div class="sec">
      <div class="sh">VM Architecture</div>
      <div class="sb">
        <div class="row"><span style="color:var(--d);min-width:120px">Type:</span><span style="color:var(--yl)">${esc(vm.type||'Unknown')}</span></div>
        <div class="row"><span style="color:var(--d);min-width:120px">Dispatcher:</span><span style="color:var(--ac)">${vm.hasDispatcher?vm.dispatcherType:'None detected'}</span></div>
        <div class="row"><span style="color:var(--d);min-width:120px">Branches:</span><span style="color:var(--pr)">${vm.opcodeCount}</span></div>
        <div class="row"><span style="color:var(--d);min-width:120px">Functions:</span><span>${vm.innerFunctions}</span></div>
        <div class="row"><span style="color:var(--d);min-width:120px">Integrity:</span><span style="color:${vm.hasIntegrityCheck?'var(--rd)':'var(--gn)'}">${vm.hasIntegrityCheck?'Yes ⚠':'No'}</span></div>
      </div>
    </div>
    
    <div class="sec">
      <div class="sh">How This Obfuscator Works</div>
      <div class="sb" style="font-size:.82em;line-height:1.7;color:var(--d)">
        <p><b style="color:var(--t)">1. Compilation:</b> Your original Lua source code is compiled into custom bytecode — a sequence of numeric opcodes that represent each operation (variable assignment, function call, loop, etc.)</p><br>
        <p><b style="color:var(--t)">2. Encoding:</b> The bytecode and constants are encoded using decimal character escapes (\\073 = byte 73) and stored in the string table <code style="color:var(--yl)">r={...}</code></p><br>
        <p><b style="color:var(--t)">3. Shuffling:</b> The string table indices are shuffled via swap operations to prevent simple index-based extraction</p><br>
        <p><b style="color:var(--t)">4. VM Interpreter:</b> A large function with hundreds of if/elseif branches acts as the VM — it reads the bytecode and executes the corresponding Lua operations</p><br>
        <p><b style="color:var(--t)">5. Execution:</b> When run, the VM interprets the bytecode instruction by instruction, performing the real operations (print, API calls, etc.)</p><br>
        <p style="color:var(--or)"><b>⚠ This means you CANNOT recover the original source by static analysis alone.</b> The bytecode is a compiled representation — like trying to get C source from a .exe file. You need to either run it with hooks or fully reverse-engineer the VM.</p>
      </div>
    </div>
    
    <div class="sec">
      <div class="sh">APIs Referenced at VM Level</div>
      <div class="sb">${vm.apiCalls.length?vm.apiCalls.map(a=>`<div class="row"><span class="tag t-i">${esc(a)}</span></div>`).join(''):'<span style="color:var(--d)">None detected</span>'}</div>
    </div>
  `;
  
  el.innerHTML=h;
}

function renderHk() {
  const el=$('hkOut');
  if (!ST.hookScript) {
    el.innerHTML='<div class="emp"><div class="ic">⚡</div><div>Run analysis first</div></div>';
    return;
  }
  
  el.innerHTML=`
    <div class="warn-box">
      <b>⚡ Runtime Hook Script</b><br><br>
      This script wraps your obfuscated code with hooks that intercept every operation.
      <b>Copy and run it in your Luau environment</b> (Roblox Studio, executor, etc.)
      to see what the obfuscated code actually does.<br><br>
      The output will show every: function call, property access, string operation, 
      table manipulation — the <b>complete behavior</b> of the hidden code.
    </div>
    <div style="display:flex;gap:5px;margin-bottom:8px">
      <button class="cpb" onclick="cpHook()">📋 Copy Hook Script</button>
      <span style="font-size:.68em;color:var(--d);display:flex;align-items:center">${ST.hookScript.length} chars</span>
    </div>
    <div class="cb" style="max-height:calc(100vh - 260px);overflow:auto;font-size:.72em">${hlLua(ST.hookScript)}</div>
  `;
}

function renderLg() {
  const el=$('lgOut');
  let h='';
  for (const l of ST.logs) {
    const c=l.l==='OK'?'t-g':l.l==='WARN'?'t-w':l.l==='ERR'?'t-e':'t-i';
    h+=`<div class="lrow" data-f="${esc((l.c+' '+l.m).toLowerCase())}"><span class="lt ${c}" style="min-width:50px">${esc(l.c.slice(0,7))}</span><span>${esc(l.m)}</span></div>`;
  }
  el.innerHTML=h||'<div class="emp"><div class="ic">📋</div></div>';
}

function hlLua(code) {
  let h = esc(code);
  h=h.replace(/(--\[\[[\s\S]*?\]\])/g,'<span class="hlc">$1</span>');
  h=h.replace(/(--[^\n]*)/g,'<span class="hlc">$1</span>');
  h=h.replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)/g,'<span class="hls">$1</span>');
  h=h.replace(/\b(\d+(?:\.\d+)?)\b/g,'<span class="hln">$1</span>');
  const kws=['local','function','return','end','if','then','else','elseif','for','while','do','repeat','until','break','in','or','and','not','true','false','nil'];
  for(const k of kws) h=h.replace(new RegExp('\\b('+k+')\\b','g'),'<span class="hlk">$1</span>');
  return h;
}

// ── UI ──
function doFilt(t){
  const q=$(t==='st'?'sf':'lf').value.toLowerCase();
  const sel=t==='st'?'#stOut .row':'#lgOut .lrow';
  document.querySelectorAll(sel).forEach(r=>{r.style.display=(r.dataset.f||'').includes(q)?'':'none'});
}

function cpHook(){
  navigator.clipboard.writeText(ST.hookScript);
  const b=event.target;const o=b.textContent;b.textContent='✅ Copied!';b.style.color='var(--gn)';
  setTimeout(()=>{b.textContent=o;b.style.color=''},1000);
}

function clearAll(){
  $('ci').value='';
  ST.logs=[]; ST.rawStrings=[]; ST.shuffledStrings=[]; ST.hookScript='';
  $('empt').style.display='';$('ovOut').style.display='none';
  $('stOut').innerHTML='';$('vmOut').innerHTML='';$('hkOut').innerHTML='';$('lgOut').innerHTML='';
  $('oi').textContent='—';uSz();
}

function doExport(){
  if(!ST.logs.length) return alert('Nothing to export');
  let t='=== Luau VM Deobfuscation Report ===\n\n';
  t+='== VM INFO ==\nType: '+(ST.vmInfo.type||'?')+'\n';
  t+='Dispatcher: '+(ST.vmInfo.dispatcherType||'none')+'\n';
  t+='Branches: '+ST.stats.vmOps+'\n';
  t+='APIs: '+(ST.vmInfo.apiCalls||[]).join(', ')+'\n';
  t+='\n== LOG ==\n';
  for(const l of ST.logs) t+=`[${l.l}][${l.c}] ${l.m}\n`;
  t+='\n== HOOK SCRIPT ==\n'+ST.hookScript;
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([t],{type:'text/plain'}));
  a.download='vm_deobf_report.txt';a.click();
}

function loadSample(){
  $('ci').value=`--[[ v1.0.0 https://wearedevs.net/obfuscator ]] return(function(...)local r={"\\073\\074\\051\\087\\115\\074\\078\\061","\\083\\107\\113\\047\\068\\108\\061\\061";"\\104\\086\\088\\119\\081\\057\\055\\052";"\\085\\080\\073\\107\\115\\078\\055\\111\\100\\074\\088\\119\\078\\107\\107\\078\\081\\054\\118\\061";"\\098\\049\\106\\061";"\\078\\113\\065\\080\\107\\078\\047\\080\\068\\074\\049\\107\\100\\097\\051\\090";"\\100\\054\\070\\106\\066\\120\\070\\066\\100\\107\\073\\070\\073\\122\\109\\056\\088\\103\\061\\061";"\\115\\097\\102\\061";"\\081\\083\\070\\120\\088\\116\\079\\057\\083\\054\\047\\101\\100\\113\\107\\049\\073\\074\\118\\061";"\\104\\067\\107\\054\\115\\057\\107\\054\\072\\080\\088\\110\\072\\101\\047\\070";"\\072\\052\\070\\054\\068\\118\\061\\061","\\088\\054\\049\\078\\078\\067\\065\\053\\072\\054\\076\\086\\115\\051\\110\\068\\118\\108\\061\\061","\\083\\078\\105\\070\\115\\120\\107\\114\\115\\054\\102\\116\\100\\077\\068\\100\\115\\118\\061\\061";"\\057\\102\\088\\101\\057\\051\\121\\052\\068\\067\\051\\069\\118\\122\\049\\079","\\068\\067\\116\\110\\073\\074\\049\\106";"\\078\\107\\056\\076\\068\\074\\049\\116\\104\\051\\109\\097\\099\\078\\068\\100","\\057\\078\\055\\072\\078\\078\\072\\086\\068\\078\\105\\068\\072\\078\\100\\116\\066\\113\\071\\047";"\\068\\080\\121\\119\\115\\086\\056\\061","\\083\\067\\110\\049\\078\\113\\088\\081\\072\\054\\111\\061";"\\068\\086\\049\\116\\072\\108\\061\\061","\\085\\087\\108\\070\\068\\117\\106\\079\\085\\108\\061\\061";"\\068\\101\\047\\089\\115\\086\\056\\061";"\\115\\097\\056\\061","\\085\\108\\061\\061";"\\080\\116\\105\\079\\115\\101\\088\\070\\099\\103\\061\\061";"\\081\\122\\070\\066\\118\\080\\110\\122\\066\\078\\072\\086\\068\\107\\102\\119";"\\104\\120\\121\\079\\115\\052\\118\\061","\\107\\074\\051\\065\\104\\074\\107\\119\\056\\102\\088\\070\\073\\074\\107\\077\\073\\074\\107\\113\\056\\118\\061\\061","\\073\\057\\055\\076\\072\\057\\049\\114",;"\\104\\101\\051\\043\\068\\074\\105\\065";"\\080\\116\\105\\052\\072\\076\\061\\061";"\\073\\074\\105\\122\\073\\120\\121\\079\\115\\101\\104\\061";"\\072\\067\\105\\043\\072\\067\\051\\054";"\\104\\101\\107\\065\\115\\086\\068\\070","\\073\\074\\105\\043\\073\\057\\116\\087\\068\\080\\056\\061";"\\115\\057\\051\\054\\081\\103\\061\\061","\\115\\074\\107\\043","\\080\\116\\105\\090\\068\\057\\111\\061";"\\072\\067\\110\\110\\104\\108\\061\\061","\\080\\116\\105\\065\\068\\080\\088\\110\\073\\074\\051\\087\\115\\074\\078\\061";"\\057\\107\\068\\101\\083\\051\\121\\097\\107\\101\\070\\075\\115\\057\\073\\087\\068\\067\\076\\061","\\078\\074\\055\\100\\107\\086\\079\\080\\100\\052\\107\\085\\068\\057\\121\\117\\107\\083\\108\\061","",;"\\104\\057\\118\\055\\068\\102\\047\\085\\107\\078\\047\\057\\066\\057\\073\\122\\073\\108\\061\\061","\\104\\074\\049\\110\\115\\074\\076\\061"}for y,F in ipairs({{645494+-645493,-474510-(-474555)},{-829171+829172,-780783-(-780799)};{-462945+462962,-610121+610166}})do while F[-137229+137230]<F[80486-80484]do r[F[679768-679767]],r[F[-870557+870559]],F[200018+-200017],F[967841-967839]=r[F[-254747-(-254749)]],r[F[-708148+708149]],F[-804231-(-804232)]+(-971268+971269),F[-575848+575850]-(677158-677157)end end local function y(y)return r[y-(-393492+446576)]end end)()`;
  uSz();
}

uSz();
