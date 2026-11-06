"""Module registry, presets and the -m option parser (same syntax as Wapiti).

Examples of -m values:
    common                  default set
    all                     every module
    passive                 only passive modules
    xss,sql                 only these two
    common,-xss             default set without xss
    all,xss:get             all modules, xss restricted to GET parameters
    ""                      (empty string) crawl only, no attack
"""
from typing import Dict, Optional, Set, Type

from protest.active.base import Attack
from protest.active.mod_access import ModuleAccessControl
from protest.active.mod_discovery import (
    ModuleBackup, ModuleBuster, ModuleHtaccess, ModuleMethods, ModuleSsl, ModuleWapp,
)
from protest.active.mod_exec import ModuleExec
from protest.active.mod_file import ModuleFile
from protest.active.mod_forms import ModuleBruteLoginForm, ModuleCsrf
from protest.active.mod_injection import ModuleCrlf, ModuleLdap, ModuleRedirect, ModuleShellshock, ModuleXxe
from protest.active.mod_sql import ModuleSql, ModuleTimesql
from protest.active.mod_xss import ModulePermanentxss, ModuleXss
from protest.passive.checks import PASSIVE_MODULES

ACTIVE_MODULES: Dict[str, Type[Attack]] = {
    cls.name: cls for cls in (
        ModuleAccessControl, ModuleBackup, ModuleBruteLoginForm, ModuleBuster, ModuleCrlf, ModuleCsrf, ModuleExec, ModuleFile,
        ModuleHtaccess, ModuleLdap, ModuleMethods, ModulePermanentxss, ModuleRedirect, ModuleShellshock,
        ModuleSql, ModuleSsl, ModuleTimesql, ModuleWapp, ModuleXss, ModuleXxe,
    )
}

ALL_MODULES: Set[str] = set(ACTIVE_MODULES) | set(PASSIVE_MODULES)
COMMON_MODULES: Set[str] = {
    "cookieflags", "csp", "exec", "file", "http_headers", "https_redirect", "inconsistent_redirection",
    "information_disclosure", "permanentxss", "redirect", "sql", "ssl", "stacktrace_disclosure",
    "unsecure_password", "xss",
}
PRESETS = {
    "all": ALL_MODULES,
    "common": COMMON_MODULES,
    "passive": set(PASSIVE_MODULES),
}


def resolve_module_settings(module_options: Optional[str]) -> Dict[str, Set[str]]:
    """Return {module_name: {"GET", "POST"} subset} from a -m option value."""
    if module_options is None:
        module_options = "common"
    elif module_options.strip() == "":
        return {}

    activated: Dict[str, Set[str]] = {}
    for option in module_options.split(","):
        option = option.strip()
        if not option:
            continue
        method: Optional[str] = None
        if ":" in option:
            option, method = option.split(":", 1)
            method = method.upper()
            if method not in ("GET", "POST"):
                raise ValueError(f"Unknown HTTP method restriction '{method}'")
        deactivate = option.startswith("-")
        option = option.lstrip("+-")

        for module in sorted(PRESETS.get(option, {option})):
            if module not in ALL_MODULES:
                raise ValueError(f"Unable to find a module named {module}")
            if deactivate:
                if module not in activated:
                    continue
                if method:
                    activated[module].discard(method)
                    if not activated[module]:
                        activated.pop(module)
                else:
                    activated.pop(module)
            else:
                activated.setdefault(module, {"GET", "POST"})
                if method:
                    activated[module] = {method}
    return activated


def module_description(name: str) -> str:
    cls = ACTIVE_MODULES.get(name) or PASSIVE_MODULES.get(name)
    return (cls.__doc__ or "").strip() if cls else ""
