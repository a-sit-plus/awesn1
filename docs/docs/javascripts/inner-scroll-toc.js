(function () {
  "use strict";

  function decodeHash(href) {
    return decodeURIComponent((href || "").replace(/^#/, ""));
  }

  function offsetWithinScroller(node, scroller) {
    var nodeRect = node.getBoundingClientRect();
    var scrollerRect = scroller.getBoundingClientRect();
    return nodeRect.top - scrollerRect.top + scroller.scrollTop;
  }

  function setActive(toc, tocLinks, activeId) {
    toc.querySelectorAll(".md-nav__link--active").forEach(function (link) {
      link.classList.remove("md-nav__link--active");
    });

    tocLinks.forEach(function (link) {
      var href = link.getAttribute("href") || "";
      var isActive = decodeHash(href) === activeId;
      link.classList.toggle("md-nav__link--active", isActive);
    });
  }

  function clearActive(toc) {
    toc.querySelectorAll(".md-nav__link--active").forEach(function (link) {
      link.classList.remove("md-nav__link--active");
    });
    toc.querySelectorAll(".md-nav__item--active").forEach(function (item) {
      item.classList.remove("md-nav__item--active");
    });
  }

  function initInnerScrollToc() {
    var scroller = document.querySelector(".md-content__inner");
    var toc = document.querySelector(".md-sidebar--secondary");
    if (!scroller || !toc) return;

    var styles = window.getComputedStyle(scroller);
    if (styles.overflowY !== "auto" && styles.overflowY !== "scroll") return;

    var tocLinks = Array.prototype.slice.call(
      toc.querySelectorAll('a[href^="#"]')
    );
    if (!tocLinks.length) return;

    var headings = tocLinks
      .map(function (link) {
        var id = decodeHash(link.getAttribute("href") || "");
        if (!id) return null;
        var node = document.getElementById(id);
        if (!node) return null;
        return { id: id, node: node };
      })
      .filter(Boolean);

    if (!headings.length) return;

    var anchorOffset = 20;
    var activeOffset = 28;

    var ticking = false;
    var onScroll = function () {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(function () {
        var threshold = scroller.scrollTop + activeOffset;
        var current = headings[0].id;

        for (var i = 0; i < headings.length; i++) {
          var y = offsetWithinScroller(headings[i].node, scroller);
          if (y <= threshold) current = headings[i].id;
          else break;
        }

        setActive(toc, tocLinks, current);
        ticking = false;
      });
    };

    tocLinks.forEach(function (link) {
      link.addEventListener("click", function (event) {
        var id = decodeHash(link.getAttribute("href") || "");
        var match = headings.find(function (entry) {
          return entry.id === id;
        });
        if (!match) return;

        event.preventDefault();
        var top = Math.max(0, offsetWithinScroller(match.node, scroller) - anchorOffset);
        scroller.scrollTo({ top: top, behavior: "smooth" });
      });
    });

    scroller.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", function () {
      clearActive(toc);
    });
    onScroll();
  }

  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(initInnerScrollToc);
  } else {
    document.addEventListener("DOMContentLoaded", initInnerScrollToc);
  }
})();
