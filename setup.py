import os
import sys
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext as _build_ext

# Ensure src is in path for imports during build
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

try:
    from urh.dev.native import ExtensionHelper
    from urh.dev.native.ExtensionHelper import COMPILER_DIRECTIVES
except ImportError:
    # This might happen if src/urh is not yet available or path is wrong
    # But since we added it to sys.path, it should work.
    ExtensionHelper = None

# Platform-specific flags
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
        try:
            import builtins
        except ImportError:
            import __builtin__ as builtins
        builtins.__NUMPY_SETUP__ = False

        import numpy

        self.include_dirs.append(numpy.get_include())


def get_extensions():
    if ExtensionHelper is None:
        return []

    try:
        from Cython.Build import cythonize
    except ImportError:
        print("Cython not found, skipping extension compilation", file=sys.stderr)
        return []

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
