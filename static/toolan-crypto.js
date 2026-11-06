/**
 * Toolan A1 应用层加密（浏览器端）
 *
 * 信封格式 A1.<b64url(salt)>.<b64url(iv)>.<b64url(ct+tag)>：AES-256-GCM +
 * PBKDF2-HMAC-SHA256（310000 迭代），与 Go 服务端 / 安卓端 / 桌面工具互通。
 * 流式传输（文件）使用 A1L：首行 meta 信封 + 逐行数据信封。
 *
 * 能力探测优先级：
 *   1. 安卓 App WebView 注入的 Java 加密桥 window.ToolanCrypto（http 可用，
 *      密钥保留在 App 内，不进 JS 环境）
 *   2. WebCrypto（仅 https / localhost 安全上下文，密钥存 localStorage）
 *   3. 都不可用 → 明文模式（不加密，行为与旧版一致）
 *
 * 本文件必须在 gate.js 之前加载：内部包装 fetch 与 WebSocket。
 */
(function () {
    'use strict';

    var ITERATIONS = 310000;
    var SALT_BYTES = 16;
    var IV_BYTES = 12;
    var VERSION = 'A1';
    var CHUNK_BYTES = 512 * 1024;        // A1L 流式下载分块（与服务端一致）
    var UPLOAD_CHUNK_BYTES = 4 * 1024 * 1024; // 加密上传分块（与服务端一致）
    var KEY_STORAGE = 'toolan_crypto_key';
    var CRYPTO_HEADER = 'X-Toolan-Crypto';

    var bridge = function () {
        try {
            return (typeof window.ToolanCrypto !== 'undefined'
                && window.ToolanCrypto && window.ToolanCrypto.enabled
                && window.ToolanCrypto.enabled()) ? window.ToolanCrypto : null;
        } catch (e) { return null; }
    }();

    var subtle = (window.crypto && window.crypto.subtle
        && (window.isSecureContext || location.hostname === 'localhost'))
        ? window.crypto.subtle : null;

    // WebCrypto 派生密钥缓存：saltB64 → CryptoKey；加密用实例级固定 salt
    var keyCache = {};
    var instanceSaltB64 = null;

    // ------------------------------------------------------------------
    // base64url / 二进制工具
    // ------------------------------------------------------------------

    function b64urlToBytes(text) {
        var pad = '='.repeat((4 - (text.length % 4)) % 4);
        var b64 = text.replace(/-/g, '+').replace(/_/g, '/') + pad;
        var bin = atob(b64);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function bytesToB64url(bytes) {
        var bin = '';
        var chunk = 0x8000;
        for (var i = 0; i < bytes.length; i += chunk) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunk, bytes.length)));
        }
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function bytesToB64(bytes) {
        var bin = '';
        var chunk = 0x8000;
        for (var i = 0; i < bytes.length; i += chunk) {
            bin += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunk, bytes.length)));
        }
        return btoa(bin);
    }

    function b64ToBytes(b64) {
        var bin = atob(b64);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function randomBytes(n) {
        var out = new Uint8Array(n);
        (window.crypto || {}).getRandomValues ? crypto.getRandomValues(out) : out.fill(0);
        return out;
    }

    // ------------------------------------------------------------------
    // 密钥：十进制或 0x 十六进制大整数 → 最短无符号大端字节序
    // ------------------------------------------------------------------

    function parseNumericKey(text) {
        var s = String(text || '').trim();
        if (!s) throw new Error('密钥不能为空');
        var n;
        if (/^0[xX][0-9a-fA-F]+$/.test(s)) n = BigInt(s);
        else if (/^[0-9]+$/.test(s)) n = BigInt(s);
        else throw new Error('密钥只能是十进制数字，或 0x 开头的十六进制数字');
        if (n < 0n) throw new Error('密钥不能为负数');
        if (n === 0n) return new Uint8Array([0]);
        var hex = n.toString(16).padStart(2, '0');
        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    function storedKey() {
        try { return localStorage.getItem(KEY_STORAGE) || ''; } catch (e) { return ''; }
    }

    function webKey() {
        var text = storedKey().trim();
        return (subtle && text) ? text : null;
    }

    // ------------------------------------------------------------------
    // 核心原语：encryptBytes / decryptBytes
    // ------------------------------------------------------------------

    function deriveKey(saltB64, salt) {
        if (keyCache[saltB64]) return keyCache[saltB64];
        var p = parseNumericKey(webKey());
        return window.crypto.subtle.importKey('raw', p, 'PBKDF2', false, ['deriveKey'])
            .then(function (baseKey) {
                return window.crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt: salt, iterations: ITERATIONS, hash: 'SHA-256' },
                    baseKey,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']);
            })
            .then(function (key) { keyCache[saltB64] = key; return key; });
    }

    function encryptBytes(plain) {
        if (bridge) {
            var env = bridge.a1EncryptB64(bytesToB64(plain));
            if (env == null) return Promise.reject(new Error('加密失败（App 桥）'));
            return Promise.resolve(env);
        }
        if (!webKey()) return Promise.reject(new Error('未配置加密密钥'));
        if (!instanceSaltB64) instanceSaltB64 = bytesToB64url(randomBytes(SALT_BYTES));
        var salt = b64urlToBytes(instanceSaltB64);
        var iv = randomBytes(IV_BYTES);
        return deriveKey(instanceSaltB64, salt).then(function (key) {
            return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, plain);
        }).then(function (ct) {
            return VERSION + '.' + instanceSaltB64 + '.' + bytesToB64url(iv) + '.' + bytesToB64url(new Uint8Array(ct));
        });
    }

    function decryptBytes(envelope) {
        if (bridge) {
            var b64 = bridge.a1DecryptB64(envelope);
            if (b64 == null) return Promise.reject(new Error('解密失败（App 桥）'));
            return Promise.resolve(b64ToBytes(b64));
        }
        if (!webKey()) return Promise.reject(new Error('未配置加密密钥'));
        var parts = String(envelope).trim().split('.');
        if (parts.length !== 4 || parts[0] !== VERSION) return Promise.reject(new Error('密文格式不正确'));
        var salt = b64urlToBytes(parts[1]);
        var iv = b64urlToBytes(parts[2]);
        var ct = b64urlToBytes(parts[3]);
        return deriveKey(parts[1], salt).then(function (key) {
            return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, ct);
        }).then(function (plain) {
            return new Uint8Array(plain);
        });
    }

    var te = new TextEncoder();
    var td = new TextDecoder();

    function encrypt(text) { return encryptBytes(te.encode(String(text))); }
    function decrypt(envelope) {
        return decryptBytes(envelope).then(function (bytes) { return td.decode(bytes); });
    }

    function looksEncrypted(text) {
        return typeof text === 'string'
            && text.indexOf(VERSION + '.') === 0
            && text.split('.').length === 4;
    }

    // ------------------------------------------------------------------
    // 状态与密钥管理
    // ------------------------------------------------------------------

    function isActive() {
        if (bridge) return true;
        return !!webKey();
    }

    function mode() {
        if (bridge) return 'bridge';
        if (webKey()) return 'webcrypto';
        return 'none';
    }

    // ------------------------------------------------------------------
    // A1L 流式解密：fetch 响应 → {meta, blob}
    // ------------------------------------------------------------------

    function decryptStream(response) {
        return response.text().then(function (text) {
            var lines = text.split('\n');
            var meta = null;
            var parts = [];
            var chain = Promise.resolve();
            lines.forEach(function (line) {
                if (!line) return;
                chain = chain.then(function () {
                    return decryptBytes(line).then(function (bytes) {
                        if (meta === null) {
                            meta = JSON.parse(td.decode(bytes));
                        } else {
                            parts.push(bytes);
                        }
                    });
                });
            });
            return chain.then(function () {
                if (!meta) throw new Error('加密流为空');
                if (meta.size > 0) {
                    var total = parts.reduce(function (n, p) { return n + p.length; }, 0);
                    if (total !== meta.size) throw new Error('流不完整：期望 ' + meta.size + ' 字节，实际 ' + total + ' 字节');
                }
                return { meta: meta, blob: new Blob(parts) };
            });
        });
    }

    // ------------------------------------------------------------------
    // 加密分块上传（4MB/块 meta+chunk 信封 multipart，保留进度回调）
    // ------------------------------------------------------------------

    function encryptedUpload(file, opts) {
        opts = opts || {};
        var totalChunks = Math.max(1, Math.ceil(file.size / UPLOAD_CHUNK_BYTES));
        var boundary = 'toolan-enc-' + Date.now();
        var parts = [];

        function addStr(s) { parts.push(s); }

        return encryptBytes(te.encode(JSON.stringify({
            name: file.name,
            mime: file.type || 'application/octet-stream',
            size: file.size,
            folder: opts.folder || ''
        }))).then(function (metaEnv) {
            addStr('--' + boundary + '\r\n'
                + 'Content-Disposition: form-data; name="meta"\r\n\r\n'
                + metaEnv + '\r\n');
            var chain = Promise.resolve();
            var index = 0;
            function nextChunk() {
                if (index >= totalChunks) return Promise.resolve();
                var offset = index * UPLOAD_CHUNK_BYTES;
                var end = Math.min(offset + UPLOAD_CHUNK_BYTES, file.size);
                var i = index++;
                return file.slice(offset, end).arrayBuffer().then(function (buf) {
                    return encryptBytes(new Uint8Array(buf));
                }).then(function (env) {
                    addStr('--' + boundary + '\r\n'
                        + 'Content-Disposition: form-data; name="chunk"\r\n\r\n'
                        + env + '\r\n');
                    if (opts.onProgress) opts.onProgress(i + 1, totalChunks);
                    return nextChunk();
                });
            }
            chain = nextChunk();
            return chain.then(function () {
                addStr('--' + boundary + '--\r\n');
                return sendUpload(new Blob(parts), boundary, opts.query);
            });
        });
    }

    function sendUpload(body, boundary, query) {
        return new Promise(function (resolve, reject) {
            var xhr = new XMLHttpRequest();
            var url = '/upload';
            if (query) {
                var qs = Object.keys(query).map(function (k) {
                    return encodeURIComponent(k) + '=' + encodeURIComponent(query[k]);
                }).join('&');
                if (qs) url += '?' + qs;
            }
            xhr.open('POST', url, true);
            xhr.setRequestHeader('Content-Type', 'multipart/form-data; boundary=' + boundary);
            xhr.setRequestHeader(CRYPTO_HEADER, VERSION);
            xhr.onload = function () {
                var text = String(xhr.responseText || '').trim();
                var parse = function (s) {
                    try { resolve(JSON.parse(s)); } catch (e) { resolve(null); }
                };
                // 失败时把状态码与（解密后的）响应体挂到错误对象上，供页面识别 409 等场景
                var fail = function (plain) {
                    var err = new Error('HTTP ' + xhr.status + ' ' + plain);
                    err.status = xhr.status;
                    err.responseText = plain;
                    reject(err);
                };
                if (xhr.status >= 200 && xhr.status < 300) {
                    if (looksEncrypted(text)) decrypt(text).then(parse, function () { resolve(null); });
                    else parse(text);
                } else {
                    if (looksEncrypted(text)) {
                        decrypt(text).then(fail, function () {
                            var err = new Error('HTTP ' + xhr.status);
                            err.status = xhr.status;
                            reject(err);
                        });
                    } else {
                        fail(text);
                    }
                }
            };
            xhr.onerror = function () { reject(new Error('网络错误')); };
            xhr.send(body);
        });
    }

    // ------------------------------------------------------------------
    // 加密下载：PC 走 fetch + A1L 解密 + blob 保存；安卓 WebView 走原生桥
    // ------------------------------------------------------------------

    function downloadEncrypted(url, fallbackName) {
        if (bridge && bridge.download) {
            bridge.download(url);
            return Promise.resolve(true);
        }
        var headers = {};
        headers[CRYPTO_HEADER] = VERSION;
        return fetch(url, { headers: headers }).then(function (res) {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return decryptStream(res);
        }).then(function (result) {
            var blobUrl = URL.createObjectURL(result.blob);
            var a = document.createElement('a');
            a.href = blobUrl;
            a.download = (result.meta && result.meta.name) || fallbackName || 'download.bin';
            document.body.appendChild(a);
            a.click();
            setTimeout(function () { URL.revokeObjectURL(blobUrl); a.remove(); }, 4000);
            return true;
        });
    }

    // 单文件加密下载地址（store 媒体/下载入口用）
    function downloadUrl(type, path) {
        return '/api/download?type=' + encodeURIComponent(type) + '&path=' + encodeURIComponent(path);
    }

    // ------------------------------------------------------------------
    // WebSocket：握手协商 + 消息解密（store/index 的 onmessage 内调用）
    // ------------------------------------------------------------------

    function wsUrl(url) {
        if (!isActive()) return url;
        if (url.indexOf('/ws') === -1) return url;
        return url + (url.indexOf('?') === -1 ? '?' : '&') + 'crypto=' + VERSION;
    }

    function decryptMessage(data) {
        if (typeof data !== 'string' || !looksEncrypted(data)) return Promise.resolve(data);
        return decrypt(data);
    }

    // ------------------------------------------------------------------
    // fetch 包装：JSON API 自动加密请求体 / 解密响应
    // ------------------------------------------------------------------

    function shouldWrap(url) {
        if (typeof url !== 'string') return false;
        return url.indexOf('/api/') === 0 || url.indexOf('/message') === 0
            || url.indexOf('/messages') === 0 || url.indexOf('/notify') === 0;
    }

    var originalFetch = window.fetch;

    function wrappedFetch(input, init) {
        init = init || {};
        var url = typeof input === 'string' ? input : (input && input.url) || '';
        var active = isActive();

        var prepare = Promise.resolve();
        var modifiedInit = init;

        if (active && shouldWrap(url)) {
            prepare = Promise.resolve().then(function () {
                var headers = new Headers(init.headers || {});
                headers.set(CRYPTO_HEADER, VERSION);
                var bodyPromise = Promise.resolve(null);
                if (typeof init.body === 'string' && init.body) {
                    bodyPromise = encrypt(init.body);
                }
                return bodyPromise.then(function (newBody) {
                    if (newBody !== null) init.body = newBody;
                    init.headers = headers;
                    modifiedInit = init;
                });
            });
        }

        return prepare.then(function () {
            return originalFetch.call(window, input, modifiedInit);
        }).then(function (res) {
            if (!active || !shouldWrap(url)) return res;
            var ct = (res.headers.get('content-type') || '').toLowerCase();
            if (ct.indexOf('json') === -1 && ct.indexOf('text') === -1) return res; // 二进制流由调用方 decryptStream
            return res.text().then(function (text) {
                var trimmed = text.trim();
                if (!looksEncrypted(trimmed)) {
                    return new Response(text, {
                        status: res.status,
                        statusText: res.statusText,
                        headers: res.headers
                    });
                }
                return decrypt(trimmed).then(function (plain) {
                    var h = new Headers();
                    h.set('Content-Type', 'application/json');
                    return new Response(plain, { status: res.status, statusText: res.statusText, headers: h });
                }).catch(function () {
                    return new Response('{"error":"解密失败：密钥不正确"}', {
                        status: 502, statusText: 'Decrypt Failed', headers: { 'Content-Type': 'application/json' }
                    });
                });
            });
        });
    }

    if (originalFetch) window.fetch = wrappedFetch;

    // ------------------------------------------------------------------
    // 公开 API
    // ------------------------------------------------------------------

    window.ToolanA1 = {
        VERSION: VERSION,
        CHUNK_BYTES: CHUNK_BYTES,
        UPLOAD_CHUNK_BYTES: UPLOAD_CHUNK_BYTES,
        KEY_STORAGE: KEY_STORAGE,
        isActive: isActive,
        mode: mode,
        hasBridge: function () { return !!bridge; },
        setKey: function (text) {
            try { localStorage.setItem(KEY_STORAGE, String(text || '').trim()); } catch (e) { }
            keyCache = {};
            instanceSaltB64 = null;
        },
        getKey: storedKey,
        clearKey: function () {
            try { localStorage.removeItem(KEY_STORAGE); } catch (e) { }
            keyCache = {};
            instanceSaltB64 = null;
        },
        encrypt: encrypt,
        decrypt: decrypt,
        encryptBytes: encryptBytes,
        decryptBytes: decryptBytes,
        looksEncrypted: looksEncrypted,
        decryptStream: decryptStream,
        encryptedUpload: encryptedUpload,
        downloadEncrypted: downloadEncrypted,
        downloadUrl: downloadUrl,
        wsUrl: wsUrl,
        decryptMessage: decryptMessage,
        parseNumericKey: parseNumericKey
    };
})();
