const FIELD = "input, textarea, select";

function isField(target: EventTarget | null): target is HTMLElement {
  return target instanceof HTMLElement && target.matches(FIELD);
}

function pinPage() {
  if (typeof window.scrollTo === "function") {
    try {
      window.scrollTo(0, 0);
    } catch {
      /* jsdom does not implement scrollTo */
    }
  }
  document.documentElement.scrollLeft = 0;
  document.documentElement.scrollTop = 0;
  document.body.scrollLeft = 0;
  document.body.scrollTop = 0;
}

/** Keep the native page from scrolling or zooming when a field is tapped. */
export function holdNativeFieldInView(target: HTMLElement) {
  target.style.fontSize = "16px";
  pinPage();
  const scroller = target.closest("[data-native-scroll]");
  if (!(scroller instanceof HTMLElement)) return;
  const field = target.getBoundingClientRect();
  const box = scroller.getBoundingClientRect();
  if (field.bottom > box.bottom - 24 || field.top < box.top + 12) {
    scroller.scrollTop = Math.max(0, scroller.scrollTop + (field.top - box.top) - 24);
  }
}

export function installNativeFieldFocusLock() {
  const meta = document.querySelector('meta[name="viewport"]');
  if (meta) {
    meta.setAttribute(
      "content",
      "width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover, interactive-widget=overlays-content",
    );
  }
  document.addEventListener("focusin", (event) => {
    if (!isField(event.target)) return;
    holdNativeFieldInView(event.target);
    requestAnimationFrame(() => {
      if (document.activeElement === event.target) holdNativeFieldInView(event.target as HTMLElement);
    });
  });
  window.visualViewport?.addEventListener("scroll", pinPage);
  window.visualViewport?.addEventListener("resize", pinPage);
}
