// ============================================================
//  Advanced Luau Deobfuscator & Environment Analyzer
//  Web-based analysis tool
// ============================================================

// ============ GLOBAL STATE ============
const state = {
    logs: [],
    strings: {
        raw: [],
        decoded: [],
        tables: [],
        byteArrays: [],
    },
    structure: {
        globals: [],
        locals: [],
        functions: [],
        tables: [],
        metatables: [],
        upvalues: [],
    },
    flow: {
        calls: [],
        patterns: [],
        suspiciousCFF: [],
        proxyChains: [],
        loadstrings: [],
    },
    stats: {
        totalStrings: 0,
        decodedStrings: 0,
        functionsFound: 0,
        tablesFound: 0,
        suspiciousPatterns: 0,
        controlFlowScore: 0,
        obfuscationScore: 0,
        bytecodeDetected: false,
        encodingMethods: new Set(),
    },
    deobfuscatedSource: '',
};

// ============ LOGGER ============
class Logger {
    static log(category, message, level = 'INFO') {
        const entry = {
            id: state.logs.length + 1,
            timestamp: performance.now().toFixed(2),
            category,
            message,
            level,
        };
        state.logs.push(entry);
    }

    static info(cat, msg) { this.log(cat, msg, 'INFO'); }
    static warn(cat, msg) { this.log(cat, msg, 'WARN'); }
    static error(cat, msg) { this.log(cat, msg, 'ERROR'); }
    static deobf(cat, msg) { this.log(cat, msg, 'DEOBF'); }
}

// ============ STRING DEOBFUSCATOR ============
class StringDeobfuscator {

    static base64Decode(input) {
        try {
            const cleaned = input.replace(/[^A-Za-z0-9+/=]/g, '');
            if (cleaned.length % 4 !== 0 || cleaned.length < 4) return null;
            const decoded = atob(cleaned);
            return decoded;
        } catch {
            return null;
        }
    }

    static hexDecode(input) {
        const cleaned = input.replace(/[\s0x]/g, '');
        if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length % 2 !== 0) return null;
        let result = '';
        for (let i = 0; i < cleaned.length; i += 2) {
            result += String.fromCharCode(parseInt(cleaned.substr(i, 2), 16));
        }
        return result;
    }

    static xorDecrypt(input, key) {
        let result = '';
        if (typeof key === 'number') {
            for (let i = 0; i < input.length; i++) {
                result += String.fromCharCode(input.charCodeAt(i) ^ key);
            }
        } else if (typeof key === 'string') {
            for (let i = 0; i < input.length; i++) {
                result += String.fromCharCode(input.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }
        }
        return result;
    }

    static caesarDecode(input, shift) {
        let result = '';
        for (let i = 0; i < input.length; i++) {
            result += String.fromCharCode((input.charCodeAt(i) - shift + 256) % 256);
        }
        return result;
    }

    static reverseString(input) {
        return input.split('').reverse().join('');
    }

    static isPrintable(str) {
        if (!str || str.length === 0) return false;
        let printable = 0;
        const len = Math.min(str.length, 100);
        for (let i = 0; i < len; i++) {
            const c = str.charCodeAt(i);
            if ((c >= 32 && c <= 126) || c === 10 || c === 13 || c === 9) {
                printable++;
            }
        }
        return (printable / len) > 0.7;
    }

    static isLikelyText(str) {
        if (!str || str.length < 2) return false;
        // Check for common word patterns
        return /[a-zA-Z]{2,}/.test(str) || /\w+\.\w+/.test(str);
    }

    static autoDeobfuscate(input) {
        if (typeof input !== 'string' || input.length === 0) return null;
        const results = [];

        // Base64
        if (/^[A-Za-z0-9+/]+=*$/.test(input) && input.length >= 4) {
            const decoded = this.base64Decode(input);
            if (decoded && this.isPrintable(decoded)) {
                results.push({ method: 'Base64', result: decoded, confidence: 0.9 });
            }
        }

        // Hex
        const cleanHex = input.replace(/[\s0x]/g, '');
        if (/^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length >= 4 && cleanHex.length % 2 === 0) {
            const decoded = this.hexDecode(cleanHex);
            if (decoded && this.isPrintable(decoded)) {
                results.push({ method: 'Hex', result: decoded, confidence: 0.85 });
            }
        }

        // Reverse
        const reversed = this.reverseString(input);
        if (reversed !== input && this.isLikelyText(reversed) && !this.isLikelyText(input)) {
            results.push({ method: 'Reverse', result: reversed, confidence: 0.7 });
        }

        // XOR common keys
        const xorKeys = [0xFF, 0x5A, 0xA5, 0x42, 0x13, 0x37, 0x44, 0x55, 0xAA];
        for (const key of xorKeys) {
            const decoded = this.xorDecrypt(input, key);
            if (decoded && this.isPrintable(decoded) && !this.isPrintable(input)) {
                results.push({
                    method: `XOR(0x${key.toString(16).toUpperCase()})`,
                    result: decoded,
                    confidence: 0.75,
                });
                break;
            }
        }

        // Caesar
        for (let shift = 1; shift <= 25; shift++) {
            const decoded = this.caesarDecode(input, shift);
            if (decoded && this.isLikelyText(decoded) && !this.isLikelyText(input)) {
                results.push({
                    method: `Caesar(${shift})`,
                    result: decoded,
                    confidence: 0.6,
                });
                break;
            }
        }

        // Sort by confidence
        results.sort((a, b) => b.confidence - a.confidence);
        return results.length > 0 ? results[0] : null;
    }

    static decodeByteArray(arr) {
        if (!Array.isArray(arr)) return null;
        let result = '';
        for (const b of arr) {
            if (typeof b !== 'number' || b < 0 || b > 255) return null;
            result += String.fromCharCode(b);
        }
        return result;
    }

    static decodeLuaEscapes(str) {
        let result = str;
        let modified = false;

        // \xHH hex escapes
        result = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
            modified = true;
            return String.fromCharCode(parseInt(hex, 16));
        });

        // \DDD decimal escapes
        result = result.replace(/\\(\d{1,3})/g, (match, dec) => {
            const byte = parseInt(dec, 10);
            if (byte <= 255) {
                modified = true;
                return String.fromCharCode(byte);
            }
            return match;
        });

        // Standard escapes
        const escapes = { '\\n': '\n', '\\t': '\t', '\\r': '\r', '\\\\': '\\', '\\"': '"', "\\'": "'" };
        for (const [esc, ch] of Object.entries(escapes)) {
            if (result.includes(esc)) {
                result = result.split(esc).join(ch);
                modified = true;
            }
        }

        return modified ? result : null;
    }
}

// ============ PATTERN ANALYZER ============
class PatternAnalyzer {

    static analyzeObfuscationLevel(source) {
        let score = 0;
        const reasons = [];

        // Check for obfuscated variable names
        const obfVarPatterns = [
            { regex: /\b[lI1O0]{4,}\b/g, label: 'Il1O0 confusing vars', weight: 15 },
            { regex: /\b_[_0-9]{3,}\b/g, label: 'Underscore+digit vars', weight: 10 },
            { regex: /\b_0x[0-9a-fA-F]+\b/g, label: '0x-prefixed vars', weight: 15 },
            { regex: /\b[_]{2,}[a-zA-Z]\b/g, label: 'Multi-underscore vars', weight: 8 },
            { regex: /\b_[lIoO01]{5,}\b/g, label: 'Long obfuscated identifiers', weight: 20 },
        ];

        for (const pat of obfVarPatterns) {
            const matches = source.match(pat.regex);
            if (matches && matches.length > 0) {
                score += Math.min(pat.weight, matches.length * 3);
                reasons.push(`${pat.label}: ${matches.length} occurrences`);
            }
        }

        // String encoding indicators
        if (/\\x[0-9a-fA-F]{2}/.test(source)) {
            const count = (source.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
            score += Math.min(20, count);
            reasons.push(`Hex escape sequences: ${count}`);
        }

        if (/\\[0-9]{1,3}/.test(source)) {
            const count = (source.match(/\\[0-9]{1,3}/g) || []).length;
            score += Math.min(15, count);
            reasons.push(`Decimal escape sequences: ${count}`);
        }

        // Control flow flattening indicators
        const whileTrue = (source.match(/while\s*(true|1)\s*do/g) || []).length;
        if (whileTrue > 0) {
            score += whileTrue * 5;
            reasons.push(`while-true loops: ${whileTrue}`);
        }

        // String.char building
        const strCharCalls = (source.match(/string\.char/g) || []).length;
        if (strCharCalls > 3) {
            score += Math.min(15, strCharCalls * 2);
            reasons.push(`string.char calls: ${strCharCalls}`);
        }

        // Loadstring usage
        const loadstringCalls = (source.match(/loadstring|load\s*\(/g) || []).length;
        if (loadstringCalls > 0) {
            score += loadstringCalls * 10;
            reasons.push(`loadstring/load calls: ${loadstringCalls}`);
        }

        // Bit operations (common in decryptors)
        const bitOps = (source.match(/bit32\.\w+|bxor|band|bor|lshift|rshift/g) || []).length;
        if (bitOps > 3) {
            score += Math.min(15, bitOps * 2);
            reasons.push(`Bitwise operations: ${bitOps}`);
        }

        // Large string literals (possible encoded payloads)
        const largeStrings = source.match(/"[^"]{200,}"|'[^']{200,}'|\[\[[^\]]{200,}\]\]/g);
        if (largeStrings) {
            score += largeStrings.length * 10;
            reasons.push(`Large string literals: ${largeStrings.length}`);
        }

        // Long lines (common in minified/obfuscated code)
        const lines = source.split('\n');
        const longLines = lines.filter(l => l.length > 500).length;
        if (longLines > 0) {
            score += longLines * 5;
            reasons.push(`Very long lines (>500 chars): ${longLines}`);
        }

        // Ratio of non-alphanum chars
        const nonAlpha = (source.match(/[^a-zA-Z0-9\s]/g) || []).length;
        const ratio = nonAlpha / source.length;
        if (ratio > 0.35) {
            score += 10;
            reasons.push(`High symbol ratio: ${(ratio * 100).toFixed(1)}%`);
        }

        // Custom base decode patterns
        if (source.match(/[A-Za-z0-9+/]{50,}={0,2}/)) {
            score += 10;
            reasons.push('Possible Base64 payload detected');
        }

        // getfenv/setfenv
        const envManip = (source.match(/getfenv|setfenv/g) || []).length;
        if (envManip > 0) {
            score += envManip * 8;
            reasons.push(`Environment manipulation: ${envManip}`);
        }

        // pcall wrapping (anti-debug)
        const pcalls = (source.match(/pcall\s*\(/g) || []).length;
        if (pcalls > 3) {
            score += Math.min(10, pcalls * 2);
            reasons.push(`pcall usage: ${pcalls}`);
        }

        // Select("#", ...) pattern
        const selectPattern = (source.match(/select\s*\(\s*["']#["']/g) || []).length;
        if (selectPattern > 0) {
            score += selectPattern * 3;
            reasons.push(`select("#",...) pattern: ${selectPattern}`);
        }

        score = Math.min(100, score);
        state.stats.obfuscationScore = score;

        return { score, reasons };
    }

    static detectControlFlowFlattening(source) {
        const patterns = [];

        // Pattern 1: while true + variable dispatch
        const dispatchPattern = /while\s*(true|1)\s*do\s*[\s\S]*?if\s+\w+\s*==\s*\d+/g;
        let match;
        while ((match = dispatchPattern.exec(source)) !== null) {
            patterns.push({
                type: 'CFF_DISPATCH',
                position: match.index,
                snippet: match[0].substring(0, 100),
            });
        }

        // Pattern 2: Large number of numeric comparisons
        const numComparisons = (source.match(/==\s*\d+/g) || []).length;
        if (numComparisons > 10) {
            patterns.push({
                type: 'CFF_STATE_MACHINE',
                detail: `${numComparisons} numeric comparisons detected`,
            });
        }

        // Pattern 3: State variable patterns
        const stateVarPattern = /local\s+\w+\s*=\s*\d+[\s\S]*?while/g;
        while ((match = stateVarPattern.exec(source)) !== null) {
            patterns.push({
                type: 'CFF_STATE_VAR',
                position: match.index,
                snippet: match[0].substring(0, 80),
            });
        }

        state.flow.suspiciousCFF = patterns;
        return patterns;
    }

    static detectProxyFunctions(source) {
        const proxies = [];

        // Pattern: local function x(...) return y(...) end
        const proxyPattern = /local\s+function\s+(\w+)\s*\(([^)]*)\)\s*return\s+(\w+)\s*\(([^)]*)\)\s*end/g;
        let match;
        while ((match = proxyPattern.exec(source)) !== null) {
            proxies.push({
                proxy: match[1],
                params: match[2],
                target: match[3],
                targetParams: match[4],
                position: match.index,
            });
        }

        // Pattern: local x = function(...) return y(...) end
        const proxyPattern2 = /local\s+(\w+)\s*=\s*function\s*\(([^)]*)\)\s*return\s+(\w+)\s*\(([^)]*)\)\s*end/g;
        while ((match = proxyPattern2.exec(source)) !== null) {
            proxies.push({
                proxy: match[1],
                params: match[2],
                target: match[3],
                targetParams: match[4],
                position: match.index,
            });
        }

        state.flow.proxyChains = proxies;
        return proxies;
    }

    static detectLoadstrings(source) {
        const loadstrings = [];
        const patterns = [
            /loadstring\s*\(([^)]*)\)/g,
            /load\s*\(([^)]*)\)/g,
        ];

        for (const pattern of patterns) {
            let match;
            while ((match = pattern.exec(source)) !== null) {
                loadstrings.push({
                    full: match[0],
                    arg: match[1].substring(0, 200),
                    position: match.index,
                });
            }
        }

        state.flow.loadstrings = loadstrings;
        return loadstrings;
    }
}

// ============ STRUCTURE ANALYZER ============
class StructureAnalyzer {

    static analyze(source) {
        this.extractGlobals(source);
        this.extractLocals(source);
        this.extractFunctions(source);
        this.extractTables(source);
        this.extractStringLiterals(source);
        this.extractByteArrays(source);
        this.extractMetatableUsage(source);
        this.extractEnvAccess(source);
    }

    static extractGlobals(source) {
        const globals = new Set();
        const builtins = new Set([
            'string', 'table', 'math', 'bit32', 'coroutine', 'os', 'io', 'debug',
            'print', 'warn', 'error', 'assert', 'pcall', 'xpcall', 'select',
            'type', 'typeof', 'tostring', 'tonumber', 'rawget', 'rawset', 'rawequal',
            'rawlen', 'setmetatable', 'getmetatable', 'pairs', 'ipairs', 'next',
            'unpack', 'require', 'loadstring', 'load', 'newproxy', 'getfenv',
            'setfenv', 'true', 'false', 'nil', 'and', 'or', 'not', 'if', 'then',
            'else', 'elseif', 'end', 'for', 'while', 'do', 'repeat', 'until',
            'return', 'break', 'continue', 'local', 'function', 'in',
            'game', 'workspace', 'script', 'Enum', 'Instance', 'Vector3',
            'CFrame', 'Color3', 'UDim2', 'UDim', 'BrickColor', 'Ray',
        ]);

        // Find identifiers that aren't preceded by 'local' or '.'
        const identRegex = /\b([a-zA-Z_]\w*)\b/g;
        let match;
        const localVars = new Set();

        // First pass: collect locals
        const localRegex = /local\s+([a-zA-Z_]\w*)/g;
        while ((match = localRegex.exec(source)) !== null) {
            localVars.add(match[1]);
        }

        // Find function params
        const paramRegex = /function\s*\w*\s*\(([^)]*)\)/g;
        while ((match = paramRegex.exec(source)) !== null) {
            const params = match[1].split(',').map(p => p.trim()).filter(Boolean);
            params.forEach(p => {
                const name = p.replace(/\.\.\./g, '').trim();
                if (name) localVars.add(name);
            });
        }

        state.structure.globals = Array.from(globals);
    }

    static extractLocals(source) {
        const locals = [];
        const regex = /local\s+(\w+)\s*=\s*([^\n;]+)/g;
        let match;
        while ((match = regex.exec(source)) !== null) {
            locals.push({
                name: match[1],
                value: match[2].trim().substring(0, 100),
                position: match.index,
                isObfuscated: /^[_lIoO01]{4,}$/.test(match[1]) || /^_0x/.test(match[1]),
            });
        }
        state.structure.locals = locals;
    }

    static extractFunctions(source) {
        const functions = [];

        // Named functions
        const namedRegex = /(?:local\s+)?function\s+(\w+)\s*\(([^)]*)\)/g;
        let match;
        while ((match = namedRegex.exec(source)) !== null) {
            functions.push({
                name: match[1],
                params: match[2],
                position: match.index,
                isLocal: source.substring(Math.max(0, match.index - 10), match.index).includes('local'),
            });
        }

        // Anonymous function assignments
        const anonRegex = /(\w+)\s*=\s*function\s*\(([^)]*)\)/g;
        while ((match = anonRegex.exec(source)) !== null) {
            if (!functions.find(f => f.name === match[1])) {
                functions.push({
                    name: match[1],
                    params: match[2],
                    position: match.index,
                    isAnonymous: true,
                });
            }
        }

        state.structure.functions = functions;
        state.stats.functionsFound = functions.length;
    }

    static extractTables(source) {
        const tables = [];
        const regex = /(?:local\s+)?(\w+)\s*=\s*\{/g;
        let match;
        while ((match = regex.exec(source)) !== null) {
            // Try to find the matching closing brace
            let depth = 1;
            let i = match.index + match[0].length;
            while (i < source.length && depth > 0) {
                if (source[i] === '{') depth++;
                if (source[i] === '}') depth--;
                i++;
            }
            const content = source.substring(match.index + match[0].length, i - 1);

            tables.push({
                name: match[1],
                position: match.index,
                contentPreview: content.substring(0, 200),
                contentLength: content.length,
                estimatedEntries: (content.match(/,/g) || []).length + 1,
            });
        }
        state.structure.tables = tables;
        state.stats.tablesFound = tables.length;
    }

    static extractStringLiterals(source) {
        const strings = [];

        // Double-quoted strings
        const dqRegex = /"((?:[^"\\]|\\.)*)"/g;
        let match;
        while ((match = dqRegex.exec(source)) !== null) {
            if (match[1].length > 0) {
                strings.push({
                    raw: match[1],
                    position: match.index,
                    quoteType: 'double',
                });
            }
        }

        // Single-quoted strings
        const sqRegex = /'((?:[^'\\]|\\.)*)'/g;
        while ((match = sqRegex.exec(source)) !== null) {
            if (match[1].length > 0) {
                strings.push({
                    raw: match[1],
                    position: match.index,
                    quoteType: 'single',
                });
            }
        }

        // Long strings [[ ]]
        const lsRegex = /\[\[([\s\S]*?)\]\]/g;
        while ((match = lsRegex.exec(source)) !== null) {
            if (match[1].length > 0) {
                strings.push({
                    raw: match[1],
                    position: match.index,
                    quoteType: 'long',
                });
            }
        }

        state.strings.raw = strings;
        state.stats.totalStrings = strings.length;

        // Try to decode each string
        for (const str of strings) {
            // First try Lua escape decoding
            const escapedDecoded = StringDeobfuscator.decodeLuaEscapes(str.raw);
            if (escapedDecoded) {
                state.strings.decoded.push({
                    original: str.raw.substring(0, 100),
                    decoded: escapedDecoded,
                    method: 'Lua Escapes',
                    position: str.position,
                });
                state.stats.decodedStrings++;
                state.stats.encodingMethods.add('Lua Escapes');
                Logger.deobf('STRING', `Decoded Lua escapes at pos ${str.position}: "${escapedDecoded.substring(0, 60)}"`);
            }

            // Then try other methods
            const autoResult = StringDeobfuscator.autoDeobfuscate(str.raw);
            if (autoResult) {
                state.strings.decoded.push({
                    original: str.raw.substring(0, 100),
                    decoded: autoResult.result,
                    method: autoResult.method,
                    confidence: autoResult.confidence,
                    position: str.position,
                });
                state.stats.decodedStrings++;
                state.stats.encodingMethods.add(autoResult.method);
                Logger.deobf('STRING', `Decoded [${autoResult.method}] at pos ${str.position}: "${autoResult.result.substring(0, 60)}"`);
            }
        }
    }

    static extractByteArrays(source) {
        // Find patterns like {72, 101, 108, 108, 111}
        const regex = /\{\s*((?:\d{1,3}\s*,\s*){3,}\d{1,3})\s*\}/g;
        let match;
        while ((match = regex.exec(source)) !== null) {
            const nums = match[1].split(',').map(n => parseInt(n.trim(), 10));
            if (nums.every(n => n >= 0 && n <= 255)) {
                const decoded = StringDeobfuscator.decodeByteArray(nums);
                if (decoded && StringDeobfuscator.isPrintable(decoded)) {
                    state.strings.byteArrays.push({
                        bytes: nums,
                        decoded,
                        position: match.index,
                    });
                    state.stats.decodedStrings++;
                    state.stats.encodingMethods.add('Byte Array');
                    Logger.deobf('BYTE_ARRAY', `Decoded byte array at pos ${match.index}: "${decoded.substring(0, 80)}"`);
                }
            }
        }
    }

    static extractMetatableUsage(source) {
        const metatables = [];
        const regex = /setmetatable\s*\(\s*(\w*)\s*,\s*\{([^}]*)\}/g;
        let match;
        while ((match = regex.exec(source)) !== null) {
            const metamethods = [];
            const mmRegex = /__(\w+)/g;
            let mmMatch;
            while ((mmMatch = mmRegex.exec(match[2])) !== null) {
                metamethods.push('__' + mmMatch[1]);
            }
            metatables.push({
                target: match[1] || '<anonymous>',
                metamethods,
                position: match.index,
            });
        }
        state.structure.metatables = metatables;
    }

    static extractEnvAccess(source) {
        const envPatterns = [
            { regex: /getfenv\s*\((\d*)\)/g, type: 'getfenv' },
            { regex: /setfenv\s*\(([^)]*)\)/g, type: 'setfenv' },
            { regex: /debug\.\w+/g, type: 'debug_access' },
            { regex: /rawget\s*\(/g, type: 'rawget' },
            { regex: /rawset\s*\(/g, type: 'rawset' },
        ];

        for (const pat of envPatterns) {
            let match;
            while ((match = pat.regex.exec(source)) !== null) {
                Logger.warn('ENV_ACCESS', `${pat.type} detected at position ${match.index}: ${match[0]}`);
                state.flow.calls.push({
                    type: pat.type,
                    detail: match[0],
                    position: match.index,
                });
            }
        }
    }
}

// ============ CONSTANT UNFOLDER ============
class ConstantUnfolder {

    static unfoldSource(source) {
        let result = source;
        let modifications = 0;

        // Unfold simple arithmetic: (5 + 3) => 8
        result = result.replace(/\((\d+)\s*([+\-*/%])\s*(\d+)\)/g, (match, a, op, b) => {
            const na = parseFloat(a);
            const nb = parseFloat(b);
            let val;
            switch (op) {
                case '+': val = na + nb; break;
                case '-': val = na - nb; break;
                case '*': val = na * nb; break;
                case '/': val = nb !== 0 ? na / nb : null; break;
                case '%': val = nb !== 0 ? na % nb : null; break;
            }
            if (val !== null && Number.isFinite(val)) {
                modifications++;
                Logger.deobf('CONST_FOLD', `${match} => ${val}`);
                return String(val);
            }
            return match;
        });

        // Unfold bit32 operations with constants
        result = result.replace(/bit32\.bxor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            const val = parseInt(a) ^ parseInt(b);
            modifications++;
            Logger.deobf('CONST_FOLD', `${match} => ${val}`);
            return String(val);
        });

        result = result.replace(/bit32\.band\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            const val = parseInt(a) & parseInt(b);
            modifications++;
            Logger.deobf('CONST_FOLD', `${match} => ${val}`);
            return String(val);
        });

        result = result.replace(/bit32\.bor\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/g, (match, a, b) => {
            const val = parseInt(a) | parseInt(b);
            modifications++;
            Logger.deobf('CONST_FOLD', `${match} => ${val}`);
            return String(val);
        });

        // Unfold math.floor on integers
        result = result.replace(/math\.floor\s*\(\s*(\d+)\s*\)/g, (match, n) => {
            modifications++;
            return n;
        });

        if (modifications > 0) {
            Logger.info('CONST_FOLD', `Applied ${modifications} constant folding operations`);
        }

        return { result, modifications };
    }
}

// ============ SOURCE CLEANER ============
class SourceCleaner {

    static clean(source) {
        let result = source;
        const changes = [];

        // Decode hex escapes in string literals
        result = result.replace(/(["'])((?:[^"'\\]|\\.)*)\1/g, (match, quote, content) => {
            let decoded = content;
            let modified = false;

            // \xHH
            decoded = decoded.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
                const byte = parseInt(hex, 16);
                if (byte >= 32 && byte <= 126) {
                    modified = true;
                    return String.fromCharCode(byte);
                }
                return `\\x${hex}`;
            });

            // \DDD
            decoded = decoded.replace(/\\(\d{1,3})/g, (m, dec) => {
                const byte = parseInt(dec, 10);
                if (byte >= 32 && byte <= 126) {
                    modified = true;
                    return String.fromCharCode(byte);
                }
                return m;
            });

            if (modified) {
                changes.push(`String decoded: ${content.substring(0, 40)} => ${decoded.substring(0, 40)}`);
                return quote + decoded + quote;
            }
            return match;
        });

        // Remove obvious no-ops
        result = result.replace(/local\s+_\s*=\s*nil\s*;?/g, () => {
            changes.push('Removed: local _ = nil');
            return '';
        });

        // Fold constants
        const { result: folded, modifications } = ConstantUnfolder.unfoldSource(result);
        result = folded;
        if (modifications > 0) {
            changes.push(`Folded ${modifications} constant expressions`);
        }

        // Clean up multiple blank lines
        result = result.replace(/\n{3,}/g, '\n\n');

        // Remove trailing whitespace
        result = result.replace(/[ \t]+$/gm, '');

        return { result, changes };
    }
}

// ============ MAIN ANALYSIS ENGINE ============
function analyze() {
    const input = document.getElementById('inputCode').value.trim();
    if (!input) {
        alert('Please paste some Luau code to analyze.');
        return;
    }

    // Reset state
    resetState();
    showLoading(true);
    setProgress(5);

    // Use setTimeout to let UI update
    setTimeout(() => {
        try {
            performAnalysis(input);
        } catch (err) {
            Logger.error('ANALYSIS', `Error during analysis: ${err.message}`);
            console.error(err);
        }
        showLoading(false);
        setProgress(100);
        renderAll();
        setTimeout(() => setProgress(0), 1500);
    }, 50);
}

function performAnalysis(source) {
    Logger.info('INIT', '═══════════════════════════════════════');
    Logger.info('INIT', ' Luau Deobfuscator & Analyzer Started');
    Logger.info('INIT', '═══════════════════════════════════════');
    Logger.info('INIT', `Input size: ${source.length} bytes, ${source.split('\n').length} lines`);

    setProgress(10);

    // 1. Obfuscation level analysis
    Logger.info('PHASE', '▶ Phase 1: Obfuscation Level Analysis');
    const obfLevel = PatternAnalyzer.analyzeObfuscationLevel(source);
    Logger.info('OBF_LEVEL', `Obfuscation score: ${obfLevel.score}/100`);
    for (const reason of obfLevel.reasons) {
        Logger.info('OBF_DETAIL', `  • ${reason}`);
    }

    setProgress(25);

    // 2. Structure analysis
    Logger.info('PHASE', '▶ Phase 2: Structure Analysis');
    StructureAnalyzer.analyze(source);
    Logger.info('STRUCTURE', `Found: ${state.structure.functions.length} functions, ${state.structure.locals.length} locals, ${state.structure.tables.length} tables`);
    Logger.info('STRINGS', `Total strings: ${state.stats.totalStrings}, Decoded: ${state.stats.decodedStrings}`);

    setProgress(45);

    // 3. Control flow analysis
    Logger.info('PHASE', '▶ Phase 3: Control Flow Analysis');
    PatternAnalyzer.detectControlFlowFlattening(source);
    PatternAnalyzer.detectProxyFunctions(source);
    PatternAnalyzer.detectLoadstrings(source);

    if (state.flow.suspiciousCFF.length > 0) {
        Logger.warn('CFF', `Detected ${state.flow.suspiciousCFF.length} control flow flattening patterns`);
        state.stats.controlFlowScore = state.flow.suspiciousCFF.length;
    }

    if (state.flow.proxyChains.length > 0) {
        Logger.deobf('PROXY', `Found ${state.flow.proxyChains.length} proxy function chains`);
        for (const proxy of state.flow.proxyChains) {
            Logger.deobf('PROXY', `  ${proxy.proxy}(${proxy.params}) → ${proxy.target}(${proxy.targetParams})`);
        }
    }

    if (state.flow.loadstrings.length > 0) {
        Logger.warn('LOADSTRING', `⚠ Found ${state.flow.loadstrings.length} loadstring/load calls!`);
        for (const ls of state.flow.loadstrings) {
            Logger.warn('LOADSTRING', `  ${ls.full.substring(0, 100)}`);
        }
    }

    setProgress(65);

    // 4. Deep string analysis for large encoded payloads
    Logger.info('PHASE', '▶ Phase 4: Deep String / Payload Analysis');
    analyzeEncodedPayloads(source);

    setProgress(80);

    // 5. Source cleaning & deobfuscation
    Logger.info('PHASE', '▶ Phase 5: Source Deobfuscation');
    const { result: cleaned, changes } = SourceCleaner.clean(source);
    if (changes.length > 0) {
        Logger.deobf('CLEAN', `Applied ${changes.length} source transformations:`);
        for (const change of changes) {
            Logger.deobf('CLEAN', `  • ${change}`);
        }
    }
    state.deobfuscatedSource = cleaned;

    setProgress(95);

    // Summary
    Logger.info('DONE', '═══════════════════════════════════════');
    Logger.info('DONE', ' Analysis Complete');
    Logger.info('DONE', `  Strings found: ${state.stats.totalStrings}`);
    Logger.info('DONE', `  Strings decoded: ${state.stats.decodedStrings}`);
    Logger.info('DONE', `  Functions: ${state.stats.functionsFound}`);
    Logger.info('DONE', `  Tables: ${state.stats.tablesFound}`);
    Logger.info('DONE', `  Obfuscation score: ${state.stats.obfuscationScore}/100`);
    Logger.info('DONE', `  Encoding methods: ${Array.from(state.stats.encodingMethods).join(', ') || 'None detected'}`);
    Logger.info('DONE', '═══════════════════════════════════════');
}

function analyzeEncodedPayloads(source) {
    // Look for very large string literals that could be encoded bytecode/payloads
    const largeStringRegex = /\[\[([^\]]{100,})\]\]|"([^"]{100,})"|'([^']{100,})'/g;
    let match;
    while ((match = largeStringRegex.exec(source)) !== null) {
        const content = match[1] || match[2] || match[3];

        Logger.info('PAYLOAD', `Large string literal found at pos ${match.index} (${content.length} chars)`);

        // Check for Luau bytecode header
        if (content.startsWith('\x1BLuaP') || content.startsWith('\x1BLJ') ||
            content.includes('\\x1B\\x4C\\x75\\x61')) {
            Logger.warn('BYTECODE', 'Luau/LuaJIT bytecode detected!');
            state.stats.bytecodeDetected = true;
        }

        // Try to decode
        const autoResult = StringDeobfuscator.autoDeobfuscate(content);
        if (autoResult) {
            Logger.deobf('PAYLOAD', `Decoded payload [${autoResult.method}]: "${autoResult.result.substring(0, 200)}"`);
            state.strings.decoded.push({
                original: content.substring(0, 100) + '...',
                decoded: autoResult.result,
                method: autoResult.method,
                position: match.index,
                isPayload: true,
            });
        }

        // Check if it's a custom encoding (like the one in the sample)
        if (/^[!-~]{50,}$/.test(content)) {
            Logger.info('PAYLOAD', 'Possible custom base-85/base-91 encoding detected');
            state.stats.encodingMethods.add('Custom Base Encoding');

            // Try to detect the decode function nearby
            const nearbySource = source.substring(Math.max(0, match.index - 500), match.index);
            if (nearbySource.includes('string.char') || nearbySource.includes('string.byte')) {
                Logger.deobf('PAYLOAD', 'Custom decoder function detected near payload');
            }
        }
    }

    // Detect the specific pattern from the sample code
    detectSamplePattern(source);
}

function detectSamplePattern(source) {
    // Detect the obfuscation pattern from the provided sample
    // Pattern: return(function(...) ... end)(...)

    if (/return\s*\(\s*function\s*\(\.\.\.\)/.test(source)) {
        Logger.warn('PATTERN', 'Self-executing function wrapper detected (common obfuscator pattern)');
        state.stats.suspiciousPatterns++;
    }

    // Detect integrity check pattern
    if (/Integrity\s*failed|integrity\s*check/i.test(source)) {
        Logger.warn('ANTI_TAMPER', 'Integrity check / anti-tamper code detected');
        state.stats.suspiciousPatterns++;
    }

    // Detect hash verification
    if (/~=\s*\d{7,}/.test(source)) {
        Logger.warn('ANTI_TAMPER', 'Hash verification detected (numeric comparison)');
        state.stats.suspiciousPatterns++;
    }

    // Detect XOR decryption loop
    if (/bit32\.bxor\s*\([^,]+,\s*\d+\)/.test(source) && /for\s+\w+\s*=\s*1\s*,\s*#/.test(source)) {
        Logger.deobf('DECRYPT', 'XOR decryption loop detected');
        state.stats.encodingMethods.add('XOR Loop');

        // Try to extract the XOR key
        const keyMatch = source.match(/bit32\.bxor\s*\([^,]+,\s*(\d+)\)/);
        if (keyMatch) {
            Logger.deobf('DECRYPT', `XOR key: ${keyMatch[1]} (0x${parseInt(keyMatch[1]).toString(16).toUpperCase()})`);
        }
    }

    // Detect custom base decoding (base85-like from sample)
    if (/\((\w)\-33\)/.test(source) || /52200625|614125|7225|85/.test(source)) {
        Logger.deobf('ENCODING', 'Base85 (Ascii85) encoding/decoding detected');
        state.stats.encodingMethods.add('Base85/Ascii85');
    }

    // Detect string.rep usage for padding/alignment
    if (/string\.rep\s*\(\s*"\\0"\s*,/.test(source)) {
        Logger.info('PATTERN', 'Null padding pattern detected (possible alignment or buffer creation)');
    }

    // Detect Zstd/compression references
    if (/CompressionAlgorithm|Zstd|decompress/i.test(source)) {
        Logger.warn('COMPRESSION', 'Compression algorithm reference detected');
        state.stats.encodingMethods.add('Compression (Zstd)');
    }

    // Detect environment checks (anti-debug/anti-cheat)
    const envChecks = [];
    if (/pcall\s*\(\s*function\s*\(\)\s*local\s+_\s*=\s*string\.rep/.test(source)) {
        envChecks.push('string.rep capability check');
    }
    if (/type\s*\(\s*tostring\s*\(\s*\{\s*\}\s*\)\s*\)/.test(source)) {
        envChecks.push('tostring({}) type check');
    }
    if (/math\.floor\s*\(\s*math\.pi\s*\*\s*1000\s*\)/.test(source)) {
        envChecks.push('math.pi precision check');
    }
    if (/select\s*\(\s*["']#["']\s*,/.test(source)) {
        envChecks.push('select("#",...) count check');
    }

    if (envChecks.length > 0) {
        Logger.warn('ENV_CHECK', `${envChecks.length} environment verification checks detected:`);
        for (const check of envChecks) {
            Logger.warn('ENV_CHECK', `  • ${check}`);
        }
        state.stats.suspiciousPatterns += envChecks.length;
    }

    // Detect the dual-string-payload pattern (from sample)
    const longVarAssignments = source.match(/local\s+\w+\s*=\s*\[\[[^\]]{100,}\]\]/g);
    if (longVarAssignments && longVarAssignments.length >= 2) {
        Logger.warn('PAYLOAD', `${longVarAssignments.length} large string payloads assigned to variables`);
        Logger.deobf('PAYLOAD', 'Multi-part payload detected — likely concatenated before decoding');
    }

    // Detect the concatenation + decode pattern
    if (/\.\.\s*_\w+/.test(source) && /loadstring|load\s*\(/.test(source)) {
        Logger.deobf('PATTERN', 'String concatenation → decode → loadstring pipeline detected');
    }
}

// ============ RENDER FUNCTIONS ============
function renderAll() {
    renderOverview();
    renderStrings();
    renderStructure();
    renderFlow();
    renderLog();
    renderDeobfuscated();
    updateCounters();
}

function renderOverview() {
    const el = document.getElementById('overviewContent');
    document.getElementById('overviewEmpty').style.display = 'none';
    el.style.display = 'block';

    const obfLabel = state.stats.obfuscationScore >= 70 ? 'Heavily Obfuscated' :
                     state.stats.obfuscationScore >= 40 ? 'Moderately Obfuscated' :
                     state.stats.obfuscationScore >= 15 ? 'Lightly Obfuscated' : 'Minimal/None';

    const obfColor = state.stats.obfuscationScore >= 70 ? 'var(--red)' :
                     state.stats.obfuscationScore >= 40 ? 'var(--orange)' :
                     state.stats.obfuscationScore >= 15 ? 'var(--accent)' : 'var(--green)';

    el.innerHTML = `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Obfuscation Level</div>
                <div class="stat-value" style="color: ${obfColor}">${state.stats.obfuscationScore}/100</div>
                <div class="stat-sub">${obfLabel}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Strings Found</div>
                <div class="stat-value" style="color: var(--purple)">${state.stats.totalStrings}</div>
                <div class="stat-sub">${state.stats.decodedStrings} decoded</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Functions</div>
                <div class="stat-value" style="color: var(--accent)">${state.stats.functionsFound}</div>
                <div class="stat-sub">${state.flow.proxyChains.length} proxies detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Tables</div>
                <div class="stat-value" style="color: var(--cyan)">${state.stats.tablesFound}</div>
                <div class="stat-sub">${state.strings.byteArrays.length} byte arrays</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">CFF Patterns</div>
                <div class="stat-value" style="color: ${state.stats.controlFlowScore > 0 ? 'var(--orange)' : 'var(--green)'}">${state.stats.controlFlowScore}</div>
                <div class="stat-sub">Control flow flattening</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Suspicious Patterns</div>
                <div class="stat-value" style="color: ${state.stats.suspiciousPatterns > 0 ? 'var(--red)' : 'var(--green)'}">${state.stats.suspiciousPatterns}</div>
                <div class="stat-sub">${state.flow.loadstrings.length} loadstring calls</div>
            </div>
        </div>

        ${state.stats.encodingMethods.size > 0 ? `
        <div style="padding: 0 16px 16px">
            <div class="stat-card">
                <div class="stat-label">Encoding Methods Detected</div>
                <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;">
                    ${Array.from(state.stats.encodingMethods).map(m =>
                        `<span class="method-badge">${escapeHtml(m)}</span>`
                    ).join('')}
                </div>
            </div>
        </div>
        ` : ''}

        ${state.stats.bytecodeDetected ? `
        <div style="padding: 0 16px">
            <div class="stat-card" style="border-color: var(--red)">
                <div class="stat-label" style="color: var(--red)">⚠ Bytecode Detected</div>
                <div style="font-size: 0.85em; margin-top: 4px;">
                    Compiled Luau/LuaJIT bytecode was detected in the payload.
                    This cannot be deobfuscated as source — a bytecode disassembler is needed.
                </div>
            </div>
        </div>
        ` : ''}

        ${state.structure.metatables.length > 0 ? `
        <div style="padding: 0 16px 16px">
            <div class="stat-card">
                <div class="stat-label">Metatable Usage</div>
                ${state.structure.metatables.map(mt => `
                    <div style="font-size: 0.82em; margin-top: 4px;">
                        <span style="color: var(--accent)">${escapeHtml(mt.target)}</span>:
                        ${mt.metamethods.map(m => `<span class="method-badge">${m}</span>`).join(' ')}
                    </div>
                `).join('')}
            </div>
        </div>
        ` : ''}
    `;
}

function renderStrings() {
    const el = document.getElementById('stringsContent');

    if (state.strings.decoded.length === 0 && state.strings.byteArrays.length === 0 && state.strings.raw.length === 0) {
        el.innerHTML = '<div class="empty-state"><div class="icon">🔤</div><div>No strings extracted</div></div>';
        return;
    }

    let html = '<table class="string-table"><thead><tr><th>#</th><th>Method</th><th>Original</th><th>Decoded</th><th>Pos</th></tr></thead><tbody>';

    let idx = 0;

    // Decoded strings
    for (const str of state.strings.decoded) {
        idx++;
        html += `<tr>
            <td>${idx}</td>
            <td><span class="method-badge">${escapeHtml(str.method)}</span></td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary)">${escapeHtml(truncate(str.original, 60))}</td>
            <td class="decoded-str" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(truncate(str.decoded, 80))}</td>
            <td style="color:var(--text-secondary)">${str.position}</td>
        </tr>`;
    }

    // Byte arrays
    for (const ba of state.strings.byteArrays) {
        idx++;
        html += `<tr>
            <td>${idx}</td>
            <td><span class="method-badge">Byte Array</span></td>
            <td style="color:var(--text-secondary)">{${ba.bytes.slice(0, 8).join(', ')}${ba.bytes.length > 8 ? '...' : ''}}</td>
            <td class="decoded-str">${escapeHtml(truncate(ba.decoded, 80))}</td>
            <td style="color:var(--text-secondary)">${ba.position}</td>
        </tr>`;
    }

    // Raw strings (not decoded, shown in lighter color)
    if (state.strings.raw.length > 0 && state.strings.decoded.length === 0) {
        for (const str of state.strings.raw.slice(0, 50)) {
            idx++;
            html += `<tr>
                <td>${idx}</td>
                <td><span class="method-badge" style="background:rgba(139,148,158,0.15);color:var(--text-secondary)">Raw</span></td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(truncate(str.raw, 80))}</td>
                <td style="color:var(--text-secondary)">—</td>
                <td style="color:var(--text-secondary)">${str.position}</td>
            </tr>`;
        }
    }

    html += '</tbody></table>';
    el.innerHTML = html;
}

function renderStructure() {
    const el = document.getElementById('structureContent');
    let html = '<div style="padding: 16px;">';

    // Functions
    if (state.structure.functions.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px"><div class="stat-label">Functions (' + state.structure.functions.length + ')</div>';
        for (const fn of state.structure.functions) {
            const obf = /^[_lIoO01]{4,}$/.test(fn.name) || /^_0x/.test(fn.name);
            html += `<div class="tree-node">
                <span class="tree-key" style="${obf ? 'color:var(--orange)' : ''}">${escapeHtml(fn.name)}</span>
                <span class="tree-type">(${escapeHtml(fn.params || '...')})</span>
                ${fn.isLocal ? '<span class="method-badge" style="font-size:0.7em">local</span>' : ''}
                ${obf ? '<span class="method-badge" style="background:rgba(210,153,34,0.15);color:var(--orange);font-size:0.7em">obfuscated name</span>' : ''}
            </div>`;
        }
        html += '</div>';
    }

    // Local variables
    if (state.structure.locals.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px"><div class="stat-label">Local Variables (' + state.structure.locals.length + ')</div>';
        const displayed = state.structure.locals.slice(0, 50);
        for (const loc of displayed) {
            html += `<div class="tree-node">
                <span class="tree-key" style="${loc.isObfuscated ? 'color:var(--orange)' : ''}">${escapeHtml(loc.name)}</span>
                <span class="tree-type"> = ${escapeHtml(truncate(loc.value, 60))}</span>
                ${loc.isObfuscated ? '<span class="method-badge" style="background:rgba(210,153,34,0.15);color:var(--orange);font-size:0.7em">obf</span>' : ''}
            </div>`;
        }
        if (state.structure.locals.length > 50) {
            html += `<div class="tree-node" style="color:var(--text-secondary)">... and ${state.structure.locals.length - 50} more</div>`;
        }
        html += '</div>';
    }

    // Tables
    if (state.structure.tables.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px"><div class="stat-label">Tables (' + state.structure.tables.length + ')</div>';
        for (const tbl of state.structure.tables) {
            html += `<div class="tree-node">
                <span class="tree-key">${escapeHtml(tbl.name)}</span>
                <span class="tree-type">~${tbl.estimatedEntries} entries, ${tbl.contentLength} chars</span>
            </div>`;
        }
        html += '</div>';
    }

    if (html === '<div style="padding: 16px;">') {
        html += '<div class="empty-state"><div class="icon">🌳</div><div>No structure detected</div></div>';
    }

    html += '</div>';
    el.innerHTML = html;
}

function renderFlow() {
    const el = document.getElementById('flowContent');
    let html = '<div style="padding: 16px;">';

    // Control flow flattening
    if (state.flow.suspiciousCFF.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px;border-color:var(--orange)">';
        html += '<div class="stat-label" style="color:var(--orange)">⚠ Control Flow Flattening (' + state.flow.suspiciousCFF.length + ')</div>';
        for (const cff of state.flow.suspiciousCFF) {
            html += `<div class="tree-node">
                <span class="method-badge">${cff.type}</span>
                <span class="tree-type"> ${escapeHtml(truncate(cff.snippet || cff.detail || '', 80))}</span>
            </div>`;
        }
        html += '</div>';
    }

    // Proxy functions
    if (state.flow.proxyChains.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px">';
        html += '<div class="stat-label">Proxy Functions (' + state.flow.proxyChains.length + ')</div>';
        for (const proxy of state.flow.proxyChains) {
            html += `<div class="tree-node">
                <span style="color:var(--orange)">${escapeHtml(proxy.proxy)}</span>
                <span style="color:var(--text-secondary)">(${escapeHtml(proxy.params)})</span>
                <span style="color:var(--green)"> → ${escapeHtml(proxy.target)}</span>
                <span style="color:var(--text-secondary)">(${escapeHtml(proxy.targetParams)})</span>
            </div>`;
        }
        html += '</div>';
    }

    // Loadstrings
    if (state.flow.loadstrings.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px;border-color:var(--red)">';
        html += '<div class="stat-label" style="color:var(--red)">⚠ loadstring / load Calls (' + state.flow.loadstrings.length + ')</div>';
        for (const ls of state.flow.loadstrings) {
            html += `<div class="code-block" style="margin:4px 0">${escapeHtml(truncate(ls.full, 200))}</div>`;
        }
        html += '</div>';
    }

    // Env access
    const envCalls = state.flow.calls.filter(c => ['getfenv', 'setfenv', 'debug_access', 'rawget', 'rawset'].includes(c.type));
    if (envCalls.length > 0) {
        html += '<div class="stat-card" style="margin-bottom:12px">';
        html += '<div class="stat-label">Environment Access (' + envCalls.length + ')</div>';
        for (const call of envCalls) {
            html += `<div class="tree-node">
                <span class="method-badge">${call.type}</span>
                <span class="tree-type"> ${escapeHtml(call.detail)}</span>
                <span style="color:var(--text-secondary)"> @ pos ${call.position}</span>
            </div>`;
        }
        html += '</div>';
    }

    if (html === '<div style="padding: 16px;">') {
        html += '<div class="empty-state"><div class="icon">🔀</div><div>No significant flow patterns detected</div></div>';
    }

    html += '</div>';
    el.innerHTML = html;
}

function renderLog() {
    const el = document.getElementById('logContent');
    let html = '';

    for (const entry of state.logs) {
        const tagClass = entry.level === 'WARN' ? 'tag-warn' :
                        entry.level === 'ERROR' ? 'tag-error' :
                        entry.level === 'DEOBF' ? 'tag-deobf' :
                        entry.category.includes('STRING') ? 'tag-string' :
                        entry.category.includes('FLOW') || entry.category.includes('CFF') ? 'tag-flow' :
                        entry.category.includes('CONST') ? 'tag-const' :
                        'tag-info';

        html += `<div class="log-entry" data-search="${escapeHtml((entry.category + ' ' + entry.message).toLowerCase())}">
            <span class="log-tag ${tagClass}">${escapeHtml(entry.category.substring(0, 12))}</span>
            <span class="log-message">${formatLogMessage(entry.message)}</span>
        </div>`;
    }

    el.innerHTML = html || '<div class="empty-state"><div class="icon">📋</div><div>No log entries</div></div>';
}

function renderDeobfuscated() {
    const el = document.getElementById('deobfContent');

    if (!state.deobfuscatedSource) {
        el.innerHTML = '<div class="empty-state"><div class="icon">✨</div><div>No deobfuscated output</div></div>';
        return;
    }

    el.innerHTML = `
        <div style="padding: 12px 16px; display: flex; gap: 8px; align-items: center; border-bottom: 1px solid var(--border);">
            <button class="btn" onclick="copyDeobfuscated()">📋 Copy</button>
            <span style="font-size: 0.8em; color: var(--text-secondary)">
                ${state.deobfuscatedSource.length} chars
            </span>
        </div>
        <pre class="code-block" style="margin:0;border:none;border-radius:0;height:calc(100% - 48px);overflow:auto">${escapeHtml(state.deobfuscatedSource)}</pre>
    `;
}

// ============ UI HELPERS ============
function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(t => {
        if (t.textContent.toLowerCase().includes(tabName.substring(0, 4))) {
            t.classList.add('active');
        }
    });

    const content = document.getElementById('tab-' + tabName);
    if (content) content.classList.add('active');
}

function showLoading(show) {
    document.getElementById('loadingOverlay').classList.toggle('active', show);
}

function setProgress(pct) {
    document.getElementById('progressFill').style.width = pct + '%';
}

function updateCounters() {
    const input = document.getElementById('inputCode').value;
    document.getElementById('inputSize').textContent = input.length + ' bytes';
    document.getElementById('logCount').textContent = state.logs.length + ' entries';
}

function filterLogs() {
    const query = document.getElementById('logFilter').value.toLowerCase();
    document.querySelectorAll('#logContent .log-entry').forEach(el => {
        const searchText = el.getAttribute('data-search') || '';
        el.style.display = searchText.includes(query) ? '' : 'none';
    });
}

function filterStrings() {
    const query = document.getElementById('stringFilter').value.toLowerCase();
    document.querySelectorAll('#stringsContent tbody tr').forEach(tr => {
        const text = tr.textContent.toLowerCase();
        tr.style.display = text.includes(query) ? '' : 'none';
    });
}

function formatLogMessage(msg) {
    let formatted = escapeHtml(msg);
    // Highlight quoted strings
    formatted = formatted.replace(/&quot;([^&]*)&quot;/g, '<span class="str-val">"$1"</span>');
    // Highlight numbers
    formatted = formatted.replace(/\b(\d+)\b/g, '<span class="num-val">$1</span>');
    // Highlight arrows
    formatted = formatted.replace(/→/g, '<span class="highlight">→</span>');
    formatted = formatted.replace(/=&gt;/g, '<span class="highlight">=&gt;</span>');
    return formatted;
}

function escapeHtml(str) {
    if (typeof str !== 'string') return String(str);
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function truncate(str, maxLen = 100) {
    if (typeof str !== 'string') return String(str);
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '...';
}

function resetState() {
    state.logs = [];
    state.strings = { raw: [], decoded: [], tables: [], byteArrays: [] };
    state.structure = { globals: [], locals: [], functions: [], tables: [], metatables: [], upvalues: [] };
    state.flow = { calls: [], patterns: [], suspiciousCFF: [], proxyChains: [], loadstrings: [] };
    state.stats = {
        totalStrings: 0, decodedStrings: 0, functionsFound: 0, tablesFound: 0,
        suspiciousPatterns: 0, controlFlowScore: 0, obfuscationScore: 0,
        bytecodeDetected: false, encodingMethods: new Set(),
    };
    state.deobfuscatedSource = '';
}

function clearAll() {
    document.getElementById('inputCode').value = '';
    resetState();
    renderAll();
    document.getElementById('overviewEmpty').style.display = '';
    document.getElementById('overviewContent').style.display = 'none';
    updateCounters();
}

function copyDeobfuscated() {
    navigator.clipboard.writeText(state.deobfuscatedSource).then(() => {
        // Brief visual feedback
        const btn = event.target;
        const origText = btn.textContent;
        btn.textContent = '✅ Copied!';
        setTimeout(() => btn.textContent = origText, 1500);
    });
}

function exportResults() {
    if (state.logs.length === 0) {
        alert('Nothing to export. Run analysis first.');
        return;
    }

    let output = '=== Luau Deobfuscator Analysis Report ===\n';
    output += `Generated: ${new Date().toISOString()}\n`;
    output += `Obfuscation Score: ${state.stats.obfuscationScore}/100\n`;
    output += `Encoding Methods: ${Array.from(state.stats.encodingMethods).join(', ') || 'None'}\n`;
    output += '\n';

    output += '=== DECODED STRINGS ===\n';
    for (const str of state.strings.decoded) {
        output += `[${str.method}] ${str.original} => ${str.decoded}\n`;
    }

    for (const ba of state.strings.byteArrays) {
        output += `[ByteArray] {${ba.bytes.join(',')}} => ${ba.decoded}\n`;
    }

    output += '\n=== FULL LOG ===\n';
    for (const entry of state.logs) {
        output += `[${entry.level}] [${entry.category}] ${entry.message}\n`;
    }

    output += '\n=== DEOBFUSCATED SOURCE ===\n';
    output += state.deobfuscatedSource || '(no modifications)';

    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'luau_deobf_report.txt';
    a.click();
    URL.revokeObjectURL(url);
}

function loadSample() {
    document.getElementById('inputCode').value = `return(function(...)local f,e,_,Q,E,N,F,A,b,R,l,C,w=string.char,setmetatable,string.gsub,loadstring or load,unpack or table.unpack,pcall,string.pack or function(fmt,v)local r=""for i=0,3 do r=r..string.char(math.floor(v/256^i)%256)end;return r;end,5,tostring,string.sub,string.byte,{},type;local _lllloOII=E;for x=0,255 do C[x]=f(x);end;C=Enum and Enum.CompressionAlgorithm and Enum.CompressionAlgorithm.Zstd or nil;local x=string.rep;local _IlolOOlI=pcall(function()local _=string.rep("\\0",64)end);local _lllOllOO=type(tostring({}));local _oOOoIOol=setmetatable({},{__index=function()return""end});local _oOIIoool=pcall(function()return string.len("")end);local _IIlOIoIl=(function(...)return select("#",...)end)(1,2,3);local _loolIIOl=math.floor(math.pi*1000)/1000;do local i={8329,{0x1B,0x4C,0x75,0x61,0x50},b(Q)};for j,z in ipairs(i) do local i={N(Q,j%2==0 and f(E(z))or z,nil,nil)};if i[1]and N(i[2])~=not i[3]then A=5;end;end;end;f=function(i)i=R(i,A);i=_(i,"z","!!!!!");return _(i,".....",e({},{__index=function(e,_)local A,R,i,j,z=l(_,1,5);local l=(z-33)+(j-33)*85+(i-33)*7225+(R-33)*614125+(A-33)*52200625;l=l%4294967296;z=F("<I4",l);e[_]=z;return z;end}));end;local _IoIIIIOl=[[LPH),pt2k)^o5F-jpD5$OnToG'n:M0HiB#,qpJk-mg5o3Bq=')]M"T0K1L9,:Y9'.PW,m.kNG&1MpqX+Xeon0fC^r.j/@G+=\\OF+=\\OF-Q="<,pt/m0d:ls/MJP%D/:[P-nQu+2DAYb+ClWM.Nr=Q.Nr=F)]NH5+Wr6d0d:m*/MJP%]];end)(...)`;
    updateCounters();
}

// ============ INIT ============
document.getElementById('inputCode').addEventListener('input', updateCounters);
updateCounters();
