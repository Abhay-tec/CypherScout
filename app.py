import os
import importlib.util
from pathlib import Path

_pkg_dir = Path(__file__).parent / "app"
_spec = importlib.util.spec_from_file_location(
    "cypherscout_app",
    _pkg_dir / "__init__.py",
    submodule_search_locations=[str(_pkg_dir)],
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("Failed to load CypherScout app package.")

_pkg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pkg)

app = _pkg.create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
