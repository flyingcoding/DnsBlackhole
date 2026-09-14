(function () {
  try {
    var stored = localStorage.getItem("dnsblackhole.theme");
    if (stored === "light" || stored === "dark") {
      document.documentElement.dataset.theme = stored;
    }
  } catch (error) {
    // 站点数据不可用时跟随系统即可。
  }
})();
