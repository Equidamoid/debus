from distutils.core import setup
from Cython.Build import cythonize

setup(
    name='pybus',
    version='0.1',
    description='DBus wire protocol implementation',
    author='Vladimir Shapranov',
    author_email='equidamoid@gmail.com',
    url='https://github.com/Equidamoid/pybus',
    ext_modules = cythonize("pybus/pybus_struct.pyx")
)