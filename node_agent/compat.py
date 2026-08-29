"""Compatibility shims for the panel-only modules the vendored drivers touch.

The core drivers are developed inside the Zagros panel and occasionally
import panel facilities. On a node there is no panel: no database, no
legacy xray singleton, no subscription renderer. Rather than forking the
drivers (they would drift from the panel within a release), the agent
installs explicit, auditable stand-ins for exactly those modules.

Two classes of shim:

* **degraded-but-correct** — :func:`mark_for_user` reproduces the panel's
  deterministic 16-bit routing mark so sing-box can render a complete,
  operable config on a node.
* **fail-closed** — everything else raises
  :class:`PanelOnlyFeatureError`. Every call site in the drivers either
  guards these imports with ``try/except`` (and degrades on purpose) or is
  unreachable on a node; a raised error here is therefore a bug report,
  never silent wrong behaviour.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from typing import Any

INSTALLED_FLAG = "_zagros_node_compat"

# The panel prefixes per-user routing marks with a stable 16-bit tag so the
# bandwidth accounting chains can recognise them. Kept identical here — a
# node must render the SAME marks as the panel or accounting breaks.
_MARK_PREFIX = 0x7A00_0000
_MARK_KIND_OUTER = 0x00
_MARK_KIND_UP = 0x01
_MARK_KIND_DOWN = 0x02


class PanelOnlyFeatureError(RuntimeError):
    """A driver reached a panel-owned facility that a node cannot provide."""


def mark_for_user(user_id: int) -> int:
    value = int(user_id)
    if value <= 0 or value > 0xFFFF:
        raise ValueError(f"user id {value} is outside the 16-bit limiter range")
    return _MARK_PREFIX | (value << 8)


def marks_for_user(user_id: int) -> dict[str, int]:
    base = mark_for_user(user_id)
    return {
        "base": base,
        "outer": base | _MARK_KIND_OUTER,
        "up": base | _MARK_KIND_UP,
        "down": base | _MARK_KIND_DOWN,
    }


def _fail(name: str) -> Any:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise PanelOnlyFeatureError(
            f"'{name}' is panel-only and is not available on a Zagros node")
    return _raise


def _shipped_by_panel(name: str) -> bool:
    """True when the real module ships in the vendored panel tree.

    ``node_agent`` vendors a *subset* of the panel (``app.cores`` and friends).
    Whenever a module the drivers import is part of that subset, the real
    implementation must win: the stand-ins below are only for the modules the
    node genuinely does not have (database, subscription rendering, ...).
    """
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _module(name: str, **attrs: Any) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__doc__ = (  # type: ignore[attr-defined]
        f"Node-agent stand-in for the panel module '{name}' (see node_agent.compat).")
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def install() -> None:
    """Install every shim. Idempotent; safe to call at import time."""
    if getattr(sys, INSTALLED_FLAG, False):
        return

    # --- real behaviour kept identical to the panel ---------------------
    bandwidth = _module("app.platform.bandwidth",
                        mark_for_user=mark_for_user,
                        marks_for_user=marks_for_user,
                        BandwidthError=ValueError)

    # --- fail-closed stand-ins ------------------------------------------
    db = _module("app.db", GetDB=_fail("app.db.GetDB"),
                 Session=_fail("app.db.Session"), crud=None)
    db_crud = _module("app.db.crud", get_user=_fail("app.db.crud.get_user"))
    db.crud = db_crud  # type: ignore[attr-defined]
    proxy_models = _module(
        "app.models.proxy", ProxyTypes=_fail("app.models.proxy.ProxyTypes"),
        ProxyHost=_fail("app.models.proxy.ProxyHost"))
    share = _module("app.subscription.share",
                    setup_format_variables=_fail(
                        "app.subscription.share.setup_format_variables"))
    xray_config = _module("app.xray.config",
                          XRayConfig=_fail("app.xray.config.XRayConfig"))

    for name, module in (
        ("app.platform", _module("app.platform")),
        ("app.platform.bandwidth", bandwidth),
        ("app.db", db),
        ("app.db.crud", db_crud),
        ("app.models", _module("app.models")),
        ("app.models.proxy", proxy_models),
        ("app.subscription", _module("app.subscription")),
        ("app.subscription.share", share),
        ("app.xray", _module("app.xray")),
        ("app.xray.config", xray_config),
    ):
        if _shipped_by_panel(name):
            # The vendored panel tree carries the real module: never shadow it
            # with a stand-in. Registering the shim first would make every
            # later ``import app.platform.bandwidth`` resolve to the stub and
            # fail with "cannot import name ... (unknown location)".
            continue
        sys.modules.setdefault(name, module)

    setattr(sys, INSTALLED_FLAG, True)
