"""Finding the files Vigia ships with, from wherever it was started.

Every default path in the CLI is written the way it looks from a clone —
`vigia/config/default.yaml`, `vigia/corpus/seeds/seeds_validated.json`. That
works in the repo and nowhere else: after `pip install vigia`, `vigia run` in
any other directory died on

    FileNotFoundError: 'vigia/config/default.yaml'

The files are in the wheel, nothing was looking for them there. A path relative
to the working directory still wins when it exists, so a clone and a
`--config ./mine.yaml` both keep behaving as before.
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
