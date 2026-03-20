// web/scripts/bridge.js
(function () {
  let ready = false;
  const waiters = [];

  function markReady() {
    if (ready) return;
    ready = true;
    while (waiters.length) {
      const resolve = waiters.shift();
      resolve();
    }
  }

  function waitForBridge() {
    if (ready) return Promise.resolve();
    return new Promise(resolve => waiters.push(resolve));
  }

  window.addEventListener("pywebviewready", () => {
    markReady();
  });

  if (window.pywebview && window.pywebview.api) {
    markReady();
  }

  async function invokeApi(name, args) {
    await waitForBridge();
    const api = window.pywebview && window.pywebview.api;
    if (!api || typeof api[name] !== "function") {
      throw new Error(`Backend API not available: ${name}`);
    }
    return api[name](...args);
  }

  function expose(fn) {
    if (typeof fn !== "function") return;
    if (!fn.name) return;
    window[fn.name] = fn;
  }

  window.eel = new Proxy(
    {
      expose,
      isReady: () => ready,
    },
    {
      get(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop !== "string") return undefined;

        return (...args) => {
          // Keep legacy call signature compatibility: eel.some_method(args...)()
          return () => invokeApi(prop, args);
        };
      },
    }
  );
})();
