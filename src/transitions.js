/**
 * PhishGuard - Smooth Interface Transition Coordinator
 * Coordinates zero-reload, dimension-preserving transitions across Safe,
 * Phishing/Suspicious, Confirmation, and Manual URL Scanner views.
 */
(function (globalScope) {
  'use strict';

  const STAGE_TIMINGS = {
    leaveMs: 240,
    enterMs: 320,
    washMs: 360,
    headerMs: 260,
  };

  // Canonical inline SVG for the Safe Website status tick icon (reused by app.js and scanner.js)
  const SAFE_TICK_SVG = [
    '<svg class="status-icon status-icon-safe" viewBox="0 0 24 24" fill="none" aria-hidden="true">',
    '  <path class="pg-safe-circle" d="M 12 3 a 9 9 0 1 1 0 18 a 9 9 0 1 1 0 -18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    '  <path class="pg-safe-check" d="M 8.85 12.15 L 10.95 14.25 L 15.15 9.75" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round"/>',
    '</svg>',
  ].join('\n');

  const stageStates = new WeakMap();

  function prefersReducedMotion() {
    return (
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    );
  }

  function forceReflow(el) {
    if (el && typeof el.offsetWidth === 'number') {
      void el.offsetWidth;
    }
  }

  function playVideo(videoEl) {
    if (!videoEl) return;
    videoEl.muted = true;
    videoEl.defaultMuted = true;
    try {
      const p = videoEl.play();
      if (p && typeof p.catch === 'function') {
        p.catch(function () {});
      }
    } catch (_) {
      // Ignore autoplay restrictions
    }
  }

  function playAllVideos(root) {
    const scope = root || (typeof document !== 'undefined' ? document : null);
    if (!scope || typeof scope.querySelectorAll !== 'function') return;
    const videos = scope.querySelectorAll('.bg-video, .panel-background-video');
    if (videos && typeof videos.forEach === 'function') {
      videos.forEach(playVideo);
    }
  }

  function getStageState(stageEl) {
    let state = stageStates.get(stageEl);
    if (!state) {
      state = { token: 0, timers: [] };
      stageStates.set(stageEl, state);
    }
    return state;
  }

  function clearStageState(stageEl, state) {
    state.token += 1;
    state.timers.forEach(function (id) {
      clearTimeout(id);
    });
    state.timers = [];

    if (!stageEl) return;

    if (typeof stageEl.querySelectorAll === 'function') {
      const ghosts = stageEl.querySelectorAll('[data-pg-ghost="true"]');
      if (ghosts && typeof ghosts.forEach === 'function') {
        ghosts.forEach(function (node) {
          if (typeof node.remove === 'function') node.remove();
        });
      }
    }

    const children = stageEl.children;
    if (children) {
      for (let i = 0; i < children.length; i += 1) {
        const child = children[i];
        if (!child) continue;
        if (child.getAttribute && child.getAttribute('data-pg-ghost') === 'true') {
          if (typeof child.remove === 'function') child.remove();
          continue;
        }
        if (child.classList) {
          child.classList.remove('panel-view-entering', 'panel-view-leaving');
        }
      }
    }
  }

  function stripCloneIdsAndSyncScroll(sourceEl, cloneEl) {
    if (!cloneEl) return;
    if (typeof cloneEl.removeAttribute === 'function') {
      cloneEl.removeAttribute('id');
    }
    cloneEl.setAttribute('aria-hidden', 'true');
    cloneEl.setAttribute('data-pg-ghost', 'true');

    if (cloneEl.classList) {
      cloneEl.classList.remove('panel-view-entering', 'panel-view-leaving');
    }

    if (typeof cloneEl.querySelectorAll === 'function') {
      cloneEl.querySelectorAll('[id]').forEach(function (node) {
        node.removeAttribute('id');
      });
      cloneEl.querySelectorAll('[for]').forEach(function (node) {
        node.removeAttribute('for');
      });
    }

    // Preserve scroll position of common scrollable containers so outgoing layer does not jump to top
    if (typeof sourceEl.scrollTop === 'number') {
      cloneEl.scrollTop = sourceEl.scrollTop;
    }
    if (typeof sourceEl.querySelectorAll === 'function' && typeof cloneEl.querySelectorAll === 'function') {
      const srcScrollables = sourceEl.querySelectorAll(
        '.checks-list, .url-field, .scanner-summary-col, .scanner-reasons-list, .scanner-features-grid'
      );
      const dstScrollables = cloneEl.querySelectorAll(
        '.checks-list, .url-field, .scanner-summary-col, .scanner-reasons-list, .scanner-features-grid'
      );
      const count = Math.min(srcScrollables.length, dstScrollables.length);
      for (let i = 0; i < count; i += 1) {
        dstScrollables[i].scrollTop = srcScrollables[i].scrollTop;
      }
    }
  }

  function createGhostSnapshot(sourceEl, displayMode) {
    if (!sourceEl || typeof sourceEl.cloneNode !== 'function') return null;
    if (sourceEl.style && sourceEl.style.display === 'none') return null;
    const clone = sourceEl.cloneNode(true);
    stripCloneIdsAndSyncScroll(sourceEl, clone);
    if (clone.style) {
      clone.style.display = displayMode || 'flex';
    }
    return clone;
  }

  function hideSiblingViews(stageEl, activeViews) {
    if (!stageEl || !stageEl.children) return;
    for (let i = 0; i < stageEl.children.length; i += 1) {
      const child = stageEl.children[i];
      if (!child) continue;
      if (child.getAttribute && child.getAttribute('data-pg-ghost') === 'true') continue;
      if (activeViews.indexOf(child) === -1) {
        if (child.style) child.style.display = 'none';
        if (typeof child.setAttribute === 'function') {
          child.setAttribute('aria-hidden', 'true');
        }
        if (child.classList) {
          child.classList.remove('panel-view-entering', 'panel-view-leaving');
        }
      }
    }
  }

  function setViewVisible(viewEl, displayMode) {
    if (!viewEl) return;
    if (viewEl.style) viewEl.style.display = displayMode || 'flex';
    if (typeof viewEl.setAttribute === 'function') {
      viewEl.setAttribute('aria-hidden', 'false');
    }
  }

  function setViewHidden(viewEl) {
    if (!viewEl) return;
    if (viewEl.classList) {
      viewEl.classList.remove('panel-view-leaving', 'panel-view-entering');
    }
    if (viewEl.style) viewEl.style.display = 'none';
    if (typeof viewEl.setAttribute === 'function') {
      viewEl.setAttribute('aria-hidden', 'true');
    }
  }

  /**
   * Coordinates an overlapping fade/glide/scale transition inside a fixed-size stage
   * container without resizing the panel or delaying interactive clicks.
   */
  function switchStageView(options) {
    const opts = options || {};
    const stageEl = opts.stageEl;
    const toView = opts.toView;
    const fromView = opts.fromView;
    const displayMode = opts.displayMode || 'flex';
    const onBeforeSwap = typeof opts.onBeforeSwap === 'function' ? opts.onBeforeSwap : null;
    const cloneFrom = Boolean(opts.cloneFrom);
    const skipAnimation = Boolean(opts.skipAnimation) || prefersReducedMotion();

    if (!stageEl || !toView) {
      if (onBeforeSwap) onBeforeSwap();
      return;
    }

    const state = getStageState(stageEl);
    clearStageState(stageEl, state);
    const myToken = state.token;

    if (skipAnimation) {
      hideSiblingViews(stageEl, [toView]);
      if (onBeforeSwap) onBeforeSwap();
      setViewVisible(toView, displayMode);
      return;
    }

    let ghost = null;
    if (cloneFrom && fromView) {
      ghost = createGhostSnapshot(fromView, displayMode);
    }

    const isCrossView = Boolean(fromView && fromView !== toView);
    const keepVisible = ghost || !isCrossView ? [toView] : [toView, fromView];
    hideSiblingViews(stageEl, keepVisible);

    // Append outgoing snapshot BEFORE updating live view content
    if (ghost && typeof stageEl.appendChild === 'function') {
      stageEl.appendChild(ghost);
    }

    if (onBeforeSwap) {
      onBeforeSwap();
    }

    setViewVisible(toView, displayMode);

    const leavingEl = ghost || (isCrossView ? fromView : null);
    if (leavingEl) {
      if (typeof leavingEl.setAttribute === 'function') {
        leavingEl.setAttribute('aria-hidden', 'true');
      }
      if (leavingEl.classList) {
        leavingEl.classList.remove('panel-view-entering');
        forceReflow(leavingEl);
        leavingEl.classList.add('panel-view-leaving');
      }

      const finishLeave = function () {
        if (state.token !== myToken) return;
        if (ghost) {
          if (typeof ghost.remove === 'function') ghost.remove();
        } else if (isCrossView) {
          setViewHidden(fromView);
        }
      };

      if (typeof leavingEl.addEventListener === 'function') {
        const onLeaveEnd = function (evt) {
          if (evt && evt.target !== leavingEl) return;
          if (typeof leavingEl.removeEventListener === 'function') {
            leavingEl.removeEventListener('animationend', onLeaveEnd);
          }
          finishLeave();
        };
        leavingEl.addEventListener('animationend', onLeaveEnd);
      }

      state.timers.push(setTimeout(finishLeave, STAGE_TIMINGS.leaveMs + 30));
    }

    if (toView.classList) {
      toView.classList.remove('panel-view-leaving');
      forceReflow(toView);
      toView.classList.add('panel-view-entering');

      const finishEnter = function () {
        if (state.token !== myToken) return;
        toView.classList.remove('panel-view-entering');
      };

      if (typeof toView.addEventListener === 'function') {
        const onEnterEnd = function (evt) {
          if (evt && evt.target !== toView) return;
          if (typeof toView.removeEventListener === 'function') {
            toView.removeEventListener('animationend', onEnterEnd);
          }
          finishEnter();
        };
        toView.addEventListener('animationend', onEnterEnd);
      }

      state.timers.push(setTimeout(finishEnter, STAGE_TIMINGS.enterMs + 30));
    }
  }

  function triggerAccentWash(washEl, tone) {
    if (!washEl || prefersReducedMotion()) return;
    const normalizedTone =
      tone === 'phishing'
        ? 'phishing'
        : tone === 'suspicious'
          ? 'suspicious'
          : tone === 'neutral'
            ? 'neutral'
            : 'safe';
    if (!washEl.classList) return;

    washEl.classList.remove('is-animating', 'tone-safe', 'tone-suspicious', 'tone-phishing', 'tone-neutral');
    forceReflow(washEl);
    washEl.classList.add(`tone-${normalizedTone}`, 'is-animating');

    const prevTimer = washEl._pgWashTimer;
    if (prevTimer) clearTimeout(prevTimer);
    washEl._pgWashTimer = setTimeout(function () {
      washEl.classList.remove('is-animating');
    }, STAGE_TIMINGS.washMs + 30);
  }

  function pulseElement(el, className, durationMs) {
    if (!el || !el.classList || prefersReducedMotion()) return;
    const cls = className || 'controls-entering';
    const ms = typeof durationMs === 'number' ? durationMs : STAGE_TIMINGS.headerMs;
    el.classList.remove(cls);
    forceReflow(el);
    el.classList.add(cls);
    const prevTimer = el._pgPulseTimer;
    if (prevTimer) clearTimeout(prevTimer);
    el._pgPulseTimer = setTimeout(function () {
      el.classList.remove(cls);
    }, ms + 30);
  }

  const api = {
    STAGE_TIMINGS,
    SAFE_TICK_SVG,
    prefersReducedMotion,
    playVideo,
    playAllVideos,
    switchStageView,
    triggerAccentWash,
    pulseElement,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  globalScope.PhishGuardTransitions = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
