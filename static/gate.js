(function () {
    'use strict';
    var AUTH_PATH = '/api/auth/';
    var redirecting = false;

    function toLogin() {
        if (redirecting) return;
        redirecting = true;
        var next = location.pathname + location.search;
        location.href = '/login?next=' + encodeURIComponent(next);
    }

    function isAuthCall(url) {
        return typeof url === 'string' && url.indexOf(AUTH_PATH) === 0;
    }

    // 包装 fetch：数据接口返回 401 时跳转登录页
    var originalFetch = window.fetch;
    if (originalFetch) {
        window.fetch = function (input, init) {
            var url = typeof input === 'string' ? input : (input && input.url) || '';
            return originalFetch.apply(this, arguments).then(function (res) {
                if (res && res.status === 401 && !isAuthCall(url)) toLogin();
                return res;
            });
        };
    }

    // 包装 XHR（上传等场景）
    var originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
        this.addEventListener('load', function () {
            if (this.status === 401 && !isAuthCall(String(url))) toLogin();
        });
        return originalOpen.apply(this, arguments);
    };

    // 页面加载即校验会话，未登录直接进登录页
    originalFetch('/api/auth/status').then(function (r) { return r.json(); }).then(function (s) {
        if (!s || !s.authenticated) toLogin();
    }).catch(function () {});

    // HTTP 页面探测同端口 HTTPS 是否可信可达；可达（已装 CA）则自动升级加密连接。
    // 不可达（手机 WebView 未信任证书等）静默留在 HTTP，保证兼容性。
    if (location.protocol === 'http:') {
        try {
            originalFetch('https://' + location.host + '/api/auth/status', { credentials: 'omit' })
                .then(function (r) {
                    if (r && r.ok) {
                        location.replace('https://' + location.host + location.pathname + location.search);
                    }
                })
                .catch(function () {});
        } catch (e) {}
    }
})();
