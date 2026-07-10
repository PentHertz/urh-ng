"""Build script for URH-NG's native (Cython/C++) extension modules.

All static package metadata now lives in ``pyproject.toml``. This file exists
only to compile the Cython extensions, which needs a bit of imperative logic
that declarative config can't express (platform flags, on-the-fly device
extension discovery, the NumPy include-dir dance).
"""
import importlib.util
import os
import sys

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as _build_ext


def _load_module_from_path(name, relpath):
    """Import a single module straight from its file path.

    We deliberately avoid ``import urh...`` here: during a PEP 517 isolated
    build the ``urh`` package isn't importable yet (and importing it would drag
    in heavy runtime deps). Loading the file directly sidesteps the old, fragile
    ``from src.urh...`` imports that only worked when the repo root happened to
    be on ``sys.path``.
    """
    abspath = os.path.join(os.path.dirname(os.path.abspath(__file__)), relpath)
    spec = importlib.util.spec_from_file_location(name, abspath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ExtensionHelper = _load_module_from_path(
    "urh_build.ExtensionHelper", "src/urh/dev/native/ExtensionHelper.py"
)
COMPILER_DIRECTIVES = ExtensionHelper.COMPILER_DIRECTIVES

if sys.platform == "win32":
    OPEN_MP_FLAG = "/openmp"
    NO_NUMPY_WARNINGS_FLAG = ""
elif sys.platform == "darwin":
    OPEN_MP_FLAG = ""  # no OpenMP support in default Mac OSX compiler
    NO_NUMPY_WARNINGS_FLAG = "-Wno-#warnings"
else:
    OPEN_MP_FLAG = "-fopenmp"
    NO_NUMPY_WARNINGS_FLAG = "-Wno-cpp"


class build_ext(_build_ext):
    def finalize_options(self):
        _build_ext.finalize_options(self)
        # Prevent numpy from thinking it is still in its setup process:
        import builtins

        builtins.__NUMPY_SETUP__ = False
        import numpy

        self.include_dirs.append(numpy.get_include())


def get_extensions():
    try:
        from Cython.Build import cythonize
    except ImportError:
        print(
            "You need Cython to build URH's extensions!\n"
            "You can get it e.g. with python3 -m pip install cython.",
            file=sys.stderr,
        )
        sys.exit(1)

    filenames = [
        os.path.splitext(f)[0]
        for f in os.listdir("src/urh/cythonext")
        if f.endswith(".pyx")
    ]
    extensions = [
        Extension(
            "urh.cythonext." + f,
            ["src/urh/cythonext/" + f + ".pyx"],
            extra_compile_args=[OPEN_MP_FLAG],
            extra_link_args=[OPEN_MP_FLAG],
            language="c++",
        )
        for f in filenames
    ]

    ExtensionHelper.USE_RELATIVE_PATHS = True
    (
        device_extensions,
        device_extras,
    ) = ExtensionHelper.get_device_extensions_and_extras()
    extensions += device_extensions

    if NO_NUMPY_WARNINGS_FLAG:
        for extension in extensions:
            extension.extra_compile_args.append(NO_NUMPY_WARNINGS_FLAG)

    return cythonize(
        extensions,
        compiler_directives=COMPILER_DIRECTIVES,
        compile_time_env=device_extras,
    )


if __name__ == "__main__":
    setup(
        ext_modules=get_extensions(),
        cmdclass={"build_ext": build_ext},
    )
