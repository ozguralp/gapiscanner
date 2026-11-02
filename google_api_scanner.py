"""Source-checkout entry point for the gapiscanner engine."""

from pathlib import Path


_FRONTEND_ROOT_PATH = Path(__file__).resolve().parent
_ENGINE_PATH = _FRONTEND_ROOT_PATH / "gapiscanner_core" / "engine.py"
exec(compile(_ENGINE_PATH.read_text(encoding="utf-8"), str(_ENGINE_PATH), "exec"), globals())

# Engine functions resolve filesystem state through this global at call time.
_FRONTEND_ROOT = str(_FRONTEND_ROOT_PATH)


if __name__ == "__main__":
    main()
