// Client-side decryption for 光達開發 Wiki (link-only access).
// key = HKDF-SHA256(linkKey, salt, "lidar-wiki v2") -> AES-256-GCM
// The link key travels in the URL fragment (#k=...), which browsers never send to the server.
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
  function store(kind) { try { return window[kind]; } catch (e) { return null; } }
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
  var K_LINK = 'lw-link';

  var linkKey = keyFrom(location.hash);
  if (linkKey) {
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
  } else {
    linkKey = get(K_LINK);
  }

  function decryptWith(lk) {
    return subtle.importKey('raw', b64uDec(lk), 'HKDF', false, ['deriveBits'])
      .then(function (hk) { return subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: te.encode('lidar-wiki v2') }, hk, 256); })
      .then(function (bits) { return subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']); })
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
          encodeURIComponent(P.title + '\n' + shareUrl) + '">' +
          '<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 3C6.5 3 2 6.6 2 11c0 3.9 3.5 7.2 8.3 7.9l-.5 2.6c-.1.5.4.8.8.6l4.6-3.3C19.2 17.6 22 14.6 22 11c0-4.4-4.5-8-10-8z"/></svg>' +
          '<span>分享到 LINE</span></a>' +
        '<button class="btn" type="button" data-copy><svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg><span>複製連結</span></button>' +
        '<button class="btn ghost" type="button" data-lock><span>鎖上</span></button>' +
        '<p class="hint" style="flex-basis:100%;margin:2px 0 0">有這個連結的人都能開啟，請只分享給團隊成員。</p>';
      var cb = box.querySelector('[data-copy]');
      cb.addEventListener('click', function () {
        var label = cb.querySelector('span');
        var ok = function () { label.textContent = '已複製'; setTimeout(function () { label.textContent = '複製連結'; }, 1600); };
        var fb = function () { window.prompt('複製這個連結', shareUrl); };
        if (navigator.clipboard) navigator.clipboard.writeText(shareUrl).then(ok, fb); else fb();
      });
      box.querySelector('[data-lock]').addEventListener('click', function () { clearAll(); location.reload(); });
    });

    app.querySelectorAll('[data-enc-video]').forEach(initVideo);

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

  // Encrypted video: download on demand, decrypt, play from a Blob URL.
  // asset key = HKDF(linkKey, assetSalt, "lidar-wiki asset v1")
  function initVideo(box) {
    var video = box.querySelector('video'), btn = box.querySelector('[data-load]');
    var prog = box.querySelector('.vprog'), bar = box.querySelector('[data-bar]'), status = box.querySelector('[data-status]');
    var total = +box.dataset.size || 0, state = 'idle', pendingSeek = null;

    function setProgress(frac, text) { bar.style.width = Math.round(frac * 100) + '%'; status.textContent = text; }
    function seekAndPlay(t) {
      video.currentTime = t;
      var p = video.play(); if (p && p.catch) p.catch(function () {});
    }

    function download() {
      return fetch(box.dataset.src).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        var len = +res.headers.get('content-length') || total + 16;
        if (!res.body || !res.body.getReader) return res.arrayBuffer();
        var reader = res.body.getReader(), parts = [], got = 0;
        return (function pump() {
          return reader.read().then(function (r) {
            if (r.done) {
              var all = new Uint8Array(got), o = 0;
              parts.forEach(function (p) { all.set(p, o); o += p.length; });
              return all.buffer;
            }
            parts.push(r.value); got += r.value.length;
            setProgress(Math.min(got / len, 1), '下載中 ' + Math.min(99, Math.floor(got / len * 100)) + '%');
            return pump();
          });
        })();
      });
    }

    function load() {
      if (state !== 'idle') return;
      state = 'loading';
      btn.hidden = true; prog.hidden = false; setProgress(0, '下載中 0%');
      download().then(function (buf) {
        setProgress(1, '解密中…');
        return subtle.importKey('raw', b64uDec(linkKey), 'HKDF', false, ['deriveBits'])
          .then(function (hk) { return subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: b64uDec(box.dataset.salt), info: te.encode('lidar-wiki asset v1') }, hk, 256); })
          .then(function (bits) { return subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']); })
          .then(function (k) { return subtle.decrypt({ name: 'AES-GCM', iv: b64uDec(box.dataset.iv) }, k, buf); });
      }).then(function (plain) {
        video.src = URL.createObjectURL(new Blob([plain], { type: box.dataset.type || 'video/mp4' }));
        state = 'ready';
        prog.hidden = true;
        var poster = box.querySelector('.poster'); if (poster) poster.hidden = true;
        video.hidden = false;
        seekAndPlay(pendingSeek || 0);
      }).catch(function () {
        state = 'idle';
        prog.hidden = true; btn.hidden = false;
        btn.querySelector('[data-label]').textContent = '載入失敗，點這裡重試';
      });
    }

    btn.addEventListener('click', load);
    document.querySelectorAll('[data-seek]').forEach(function (el) {
      el.addEventListener('click', function () {
        var t = +el.dataset.seek || 0;
        box.scrollIntoView({ behavior: 'smooth', block: 'start' });
        if (state === 'ready') seekAndPlay(t);
        else { pendingSeek = t; load(); }
      });
    });
  }

  var form = $('lock-form'), err = $('err'), go = $('go');
  function showErr(msg) { err.textContent = msg; err.hidden = !msg; }
  function showForm() { form.hidden = false; $('opening').hidden = true; }

  if (!subtle) {
    showForm();
    showErr('這個瀏覽器不支援解密。請改用 Safari 或 Chrome 開啟。');
    go.disabled = true;
    return;
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var lk = keyFrom($('lk').value);
    if (!lk) { showErr('找不到金鑰。請貼上完整的分享連結。'); return; }
    showErr('');
    go.disabled = true; go.textContent = '開啟中…';
    decryptWith(lk).then(function (html) {
      linkKey = lk;
      put(K_LINK, lk, $('remember').checked);
      render(html);
    }).catch(function () {
      showErr('這個連結無法開啟，請確認是最新的分享連結。');
      go.disabled = false; go.textContent = '開啟';
    });
  });

  if (linkKey) {
    decryptWith(linkKey).then(function (html) {
      put(K_LINK, linkKey, false);
      render(html);
    }).catch(function () {
      linkKey = null;
      showForm();
      showErr('這個連結無法開啟，請確認是最新的分享連結。');
    });
  } else {
    showForm();
  }
})();
