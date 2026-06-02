(() => {
  window.startGlitch = (period) => {
    const trigger = () => {
      const targets = document.querySelectorAll(".glitch, .bgfx");
      targets.forEach((t) => t.classList.add("on"));
      setTimeout(() => targets.forEach((t) => t.classList.remove("on")), 320);
    };
    setInterval(trigger, period);
  };

  window.initToc = () => {
    const toc = document.querySelector(".toc");
    if (!toc) return;
    const head = toc.querySelector(".toc-head");
    const caret = toc.querySelector(".toc-caret");
    head.addEventListener("click", () => {
      const open = toc.classList.toggle("open");
      if (caret) caret.textContent = open ? "▾" : "▸";
      head.setAttribute("aria-expanded", open ? "true" : "false");
    });
    toc.querySelectorAll(".toc-item a").forEach((link) => {
      link.addEventListener("click", (e) => {
        const id = link.getAttribute("href").slice(1);
        const target = document.getElementById(id);
        if (!target) return;
        e.preventDefault();
        history.replaceState(null, "", "#" + id);
        window.scrollTo({
          top: target.getBoundingClientRect().top + window.scrollY - 24,
          behavior: "smooth",
        });
      });
    });
  };
})();
