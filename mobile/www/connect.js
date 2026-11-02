// B17-T1: the connect page. It asks for a deployment's address (typed or
// scanned from a QR code), checks that the address answers GET /health, keeps
// it in Preferences and moves the WebView there. Opening the app again goes
// straight to the kept address; `index.html?change` asks again.
'use strict';

(function () {
  const TEXT = {
    en: {
      title: 'Connect to Attome',
      intro: "Enter your organisation's Attome address, or scan the code your administrator shared.",
      address: 'Address',
      connect: 'Connect',
      scan: 'Scan QR',
      checking: 'Checking the address…',
      notHttps: 'The address must start with https://',
      unreachable: 'No Attome deployment answered at this address.',
      noScanner: 'Scanning is not available on this phone. Type the address instead.',
      noCamera: 'The camera could not be opened.',
    },
    ar: {
      title: 'الاتصال بـ Attome',
      intro: 'أدخل عنوان Attome الخاص بمؤسستك، أو امسح الرمز الذي شاركه المسؤول.',
      address: 'العنوان',
      connect: 'اتصال',
      scan: 'مسح رمز QR',
      checking: 'جارٍ التحقق من العنوان…',
      notHttps: 'يجب أن يبدأ العنوان بـ https://',
      unreachable: 'لم يستجب أي نظام Attome على هذا العنوان.',
      noScanner: 'المسح غير متاح على هذا الهاتف. اكتب العنوان بدلًا من ذلك.',
      noCamera: 'تعذّر فتح الكاميرا.',
    },
  };
  const KEY = 'attome.address';
  const lang = (navigator.language || 'en').toLowerCase().startsWith('ar') ? 'ar' : 'en';
  const t = TEXT[lang];

  const cap = window.Capacitor;
  const debug = Boolean(cap && cap.DEBUG);
  const prefs = cap && cap.Plugins && cap.Plugins.Preferences;

  async function load() {
    if (prefs) {
      const { value } = await prefs.get({ key: KEY });
      return value;
    }
    try {
      return window.localStorage.getItem(KEY);
    } catch {
      return null;
    }
  }

  async function save(address) {
    if (prefs) {
      await prefs.set({ key: KEY, value: address });
      return;
    }
    try {
      window.localStorage.setItem(KEY, address);
    } catch {
      // Not kept: the next start asks again.
    }
  }

  // The address as an origin, or null: https, or http to 127.0.0.1 in a
  // debug build only.
  function origin(raw) {
    let url;
    try {
      url = new URL(raw.trim());
    } catch {
      return null;
    }
    const local = url.protocol === 'http:' && url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !(debug && local)) {
      return null;
    }
    return url.origin;
  }

  async function answers(address) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(address + '/health', { signal: controller.signal });
      return response.status === 200;
    } catch {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  const form = document.getElementById('form');
  const input = document.getElementById('address');
  const message = document.getElementById('message');
  const video = document.getElementById('camera');

  async function connect(raw) {
    const address = origin(raw);
    if (!address) {
      message.textContent = t.notHttps;
      return;
    }
    message.textContent = t.checking;
    if (!(await answers(address))) {
      message.textContent = t.unreachable;
      return;
    }
    await save(address);
    window.location.href = address;
  }

  async function scan() {
    if (!('BarcodeDetector' in window) || !navigator.mediaDevices) {
      message.textContent = t.noScanner;
      return;
    }
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    } catch {
      message.textContent = t.noCamera;
      return;
    }
    const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    video.srcObject = stream;
    video.hidden = false;
    await video.play();
    const stop = () => {
      stream.getTracks().forEach(track => track.stop());
      video.hidden = true;
    };
    const look = async () => {
      if (video.hidden) {
        return;
      }
      const codes = await detector.detect(video).catch(() => []);
      if (codes.length > 0) {
        stop();
        input.value = codes[0].rawValue;
        await connect(codes[0].rawValue);
        return;
      }
      window.requestAnimationFrame(look);
    };
    window.requestAnimationFrame(look);
  }

  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-text]').forEach(node => {
    node.textContent = t[node.dataset.text];
  });
  form.addEventListener('submit', event => {
    event.preventDefault();
    connect(input.value);
  });
  document.getElementById('scan').addEventListener('click', scan);

  const change = new URLSearchParams(window.location.search).has('change');
  load().then(saved => {
    if (saved && !change && origin(saved)) {
      window.location.href = saved;
    } else if (saved) {
      input.value = saved;
    }
  });
})();
