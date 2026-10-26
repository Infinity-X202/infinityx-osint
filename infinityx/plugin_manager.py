"""Load and run local plugins from infinityx/plugins."""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from infinityx.models import CheckResult
from infinityx.plugins.base import plugin_failed

_DISABLED: set[str] = set()


def list_plugins() -> list[dict[str, Any]]:
    rows = []
    for module in _iter_plugin_modules():
        info = getattr(module, "INFO", None)
        if info is None:
            continue
        rows.append({**info.as_dict(), "enabled": info.name not in _DISABLED, "module": module.__name__})
    return rows


def set_plugin_enabled(name: str, enabled: bool) -> None:
    if enabled:
        _DISABLED.discard(name)
    else:
        _DISABLED.add(name)


def run_enabled_plugins(domain: str, context: dict[str, Any]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for module in _iter_plugin_modules():
        info = getattr(module, "INFO", None)
        if info is None or info.name in _DISABLED:
            continue
        try:
            item = module.run(domain, context)
        except Exception as exc:
            item = plugin_failed(info, f"Plugin raised: {exc}")
        if isinstance(item, CheckResult):
            item.check_id = f"plugin:{info.name}"
            item.name = f"Plugin: {info.name}"
            item.category = "Plugins"
            results.append(item)
    return results


def _iter_plugin_modules():
    package = importlib.import_module("infinityx.plugins")
    prefix = package.__name__ + "."
    for module_info in pkgutil.iter_modules(package.__path__, prefix):
        if module_info.name.endswith(".base") or ".example_" not in module_info.name:
            continue
        yield importlib.import_module(module_info.name)
