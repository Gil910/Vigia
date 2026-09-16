"""Finding the files Vigia ships with, from wherever it was started.

Every default path in the CLI is written the way it looks from a clone —
`vigia/config/default.yaml`, `vigia/corpus/seeds/seeds_validated.json`. That
works in the repo and nowhere else: after `pip install vigia`, `vigia run` in
any other directory died on

    FileNotFoundError: 'vigia/config/default.yaml'

The files are in the wheel, nothing was looking for them there. A path relative
to the working directory still wins when it exists, so a clone and a
`--config ./mine.yaml` both keep behaving as before.

v0.6.0 first shipped this applied to the argparse *defaults* only, which fixed
`vigia run` and left the documented `vigia run -c vigia/config/claude_haiku.yaml`
raising the very traceback above. It is applied where the path is opened now, so
it covers whatever the user typed as well.
"""

import os
from importlib import resources

_PREFIXES = ("./vigia/", "vigia/")


def packaged(path: str) -> str:
    """Resolve a shipped default against the installed package if need be."""
    if not path or os.path.exists(path):
        return path
    for prefix in _PREFIXES:
        if path.startswith(prefix):
            inside = path[len(prefix):]
            break
    else:
        return path
    try:
        candidate = resources.files("vigia").joinpath(inside)
    except (ModuleNotFoundError, TypeError):
        return path
    return str(candidate) if candidate.exists() else path


def resolve(path: str, what: str) -> str:
    """`packaged()`, but a missing file is a sentence rather than a traceback.

    `what` names the thing for the error message ("config", "corpus"). Raising
    SystemExit keeps the CLI's exit codes meaningful: a typo is a usage error,
    not a crash.
    """
    found = packaged(path)
    if not os.path.exists(found):
        shipped = ", ".join(sorted(
            f"vigia/config/{p.name}"
            for p in resources.files("vigia").joinpath("config").iterdir()
            if p.name.endswith(".yaml")
        )) if what == "config" else ""
        extra = f"\nShipped configs: {shipped}" if shipped else ""
        raise SystemExit(f"{path}: no such {what}.{extra}")
    return found
