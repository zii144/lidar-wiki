// Client-side decryption for 光達開發 Wiki.
// key = HKDF-SHA256( PBKDF2-SHA256(password, salt, iter) || linkKey, salt, "lidar-wiki v1" ) -> AES-256-GCM
(function () {
  var P = JSON.parse(document.getElementById('payload').textContent);
  var subtle = window.crypto && window.crypto.subtle;
  var te = new TextEncoder();
  var $ = function (id) { return document.getElementById(id); };

  function b64uDec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64uEnc(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function store(kind) {
    try { return window[kind]; } catch (e) { return null; }
  }
  function get(k) {
    var v = null;
    ['sessionStorage', 'localStorage'].some(function (s) {
      try { var st = store(s); v = st && st.getItem(k); } catch (e) { v = null; }
      return !!v;
    });
    return v;
  }
  function put(k, v, persist) {
    ['sessionStorage'].concat(persist ? ['localStorage'] : []).forEach(function (s) {
      try { store(s).setItem(k, v); } catch (e) {}
    });
  }
  function clearAll() {
    ['sessionStorage', 'localStorage'].forEach(function (s) {
      try {
        var st = store(s);
        for (var i = st.length - 1; i >= 0; i--) { var k = st.key(i); if (k && k.indexOf('lw-') === 0) st.removeItem(k); }
      } catch (e) {}
    });
  }
  function keyFrom(text) {
    if (!text) return null;
    var m = String(text).match(/[#&?]k=([A-Za-z0-9_-]{20,})/);
    if (m) return m[1];
    text = String(text).trim();
    return /^[A-Za-z0-9_-]{20,}$/.test(text) ? text : null;
  }

  var salt = b64uDec(P.salt), iv = b64uDec(P.iv), ct = b64uDec(P.ct);
  var K_LINK = 'lw-link-' + P.salt, K_KEY = 'lw-key-' + P.salt;

  var linkKey = keyFrom(location.hash);
  if (linkKey) {
    put(K_LINK, linkKey, false);
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
  } else {
    linkKey = get(K_LINK);
  }

  function derive(password, lk) {
    var lkBytes = b64uDec(lk);
    return subtle.importKey('raw', te.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits'])
      .then(function (pk) { return subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: P.iter }, pk, 256); })
      .then(function (bits) {
        var ikm = new Uint8Array(32 + lkBytes.length);
        ikm.set(new Uint8Array(bits), 0); ikm.set(lkBytes, 32);
        return subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
      })
      .then(function (hk) { return subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: te.encode('lidar-wiki v1') }, hk, 256); })
      .then(function (b) { return new Uint8Array(b); });
  }
  function decrypt(keyBytes) {
    return subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt'])
      .then(function (k) { return subtle.decrypt({ name: 'AES-GCM', iv: iv }, k, ct); })
      .then(function (pt) { return new TextDecoder().decode(pt); });
  }

  function render(html) {
    var app = $('app');
    app.innerHTML = html;
    $('lock').hidden = true;
    app.hidden = false;
    document.title = P.title;

    app.querySelectorAll('a[data-internal]').forEach(function (a) {
      if (linkKey) a.setAttribute('href', a.getAttribute('href') + '#k=' + linkKey);
    });
    app.querySelectorAll('a[href^="#s"]').forEach(function (a) {
      a.addEventListener('click', function (e) {
        var t = document.getElementById(a.getAttribute('href').slice(1));
        if (t) { e.preventDefault(); t.scrollIntoView({ behavior: 'smooth' }); }
      });
    });

    var shareUrl = location.origin + location.pathname + (linkKey ? '#k=' + linkKey : '');
    app.querySelectorAll('[data-share]').forEach(function (box) {
      box.innerHTML =
        '<a class="btn line" target="_blank" rel="noopener" href="https://line.me/R/share?text=' +
          encodeURIComponent(P.title + '\n' + shareUrl + '\n（密碼另外私訊）') + '">' +
          '<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 3C6.5 3 2 6.6 2 11c0 3.9 3.5 7.2 8.3 7.9l-.5 2.6c-.1.5.4.8.8.6l4.6-3.3C19.2 17.6 22 14.6 22 11c0-4.4-4.5-8-10-8z"/></svg>' +
          '<span>分享到 LINE</span></a>' +
        '<button class="btn" type="button" data-copy><svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg><span>複製連結</span></button>' +
        '<button class="btn ghost" type="button" data-lock><span>鎖上</span></button>' +
        '<p class="hint" style="flex-basis:100%;margin:2px 0 0">分享的連結已包含金鑰，密碼請另外私訊。</p>';
      var cb = box.querySelector('[data-copy]');
      cb.addEventListener('click', function () {
        var label = cb.querySelector('span');
        var ok = function () { label.textContent = '已複製'; setTimeout(function () { label.textContent = '複製連結'; }, 1600); };
        var fb = function () { window.prompt('複製這個連結', shareUrl); };
        if (navigator.clipboard) navigator.clipboard.writeText(shareUrl).then(ok, fb); else fb();
      });
      box.querySelector('[data-lock]').addEventListener('click', function () { clearAll(); location.reload(); });
    });

    var links = [].slice.call(app.querySelectorAll('#rail a'));
    if (links.length && 'IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (es) {
        es.forEach(function (e) {
          if (!e.isIntersecting) return;
          links.forEach(function (a) {
            var on = a.getAttribute('href') === '#' + e.target.id;
            a.classList.toggle('on', on);
            if (on) a.parentNode.scrollLeft = a.offsetLeft - 16;
          });
        });
      }, { rootMargin: '-120px 0px -60% 0px' });
      app.querySelectorAll('main section').forEach(function (s) { io.observe(s); });
    }
  }

  var form = $('lock-form'), err = $('err'), go = $('go');
  function showErr(msg) { err.textContent = msg; err.hidden = !msg; }

  if (!subtle) {
    showErr('這個瀏覽器不支援解密。請改用 Safari 或 Chrome 開啟。');
    go.disabled = true;
    return;
  }
  if (!linkKey) $('key-row').hidden = false;

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var pw = $('pw').value;
    var lk = linkKey || keyFrom($('lk').value);
    if (!lk) { showErr('缺少金鑰。請貼上完整的分享連結。'); return; }
    if (!pw) { showErr('請輸入密碼。'); return; }
    showErr('');
    go.disabled = true; go.textContent = '解鎖中…';
    var keyBytes;
    derive(pw, lk)
      .then(function (kb) { keyBytes = kb; return decrypt(kb); })
      .then(function (html) {
        var persist = $('remember').checked;
        linkKey = lk;
        put(K_LINK, lk, persist);
        put(K_KEY, b64uEnc(keyBytes), persist);
        render(html);
      })
      .catch(function () {
        showErr(linkKey ? '密碼不正確，請再試一次。' : '密碼或金鑰不正確，請再試一次。');
        go.disabled = false; go.textContent = '解鎖';
      });
  });

  var saved = get(K_KEY);
  if (saved) {
    decrypt(b64uDec(saved)).then(render).catch(function () {});
  }
})();
