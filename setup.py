import setuptools
import os
import sys
import setuptools.command.build_py
from Cython.Build import cythonize


class DeannotateAndBuild(setuptools.command.build_py.build_py):

    def build_packages(self):
        super().build_packages()
        if sys.version_info[0] == 3 and sys.version_info [1] < 6:
            print("Installing for older python, trying to clean up annotations...", file=sys.stderr)
            os.system(r'''set -x; cd %s; find . -name '*.py' | xargs -n1 sed -i '' 's@^\( *[a-zA-Z._]*\):.*=@\1 = @g' ''' % self.build_lib)


setuptools.setup(
    cmdclass={
        'build_py': DeannotateAndBuild,
    },
    name='pybus',
    version='0.1',
    description='DBus wire protocol implementation',
    author='Vladimir Shapranov',
    author_email='equidamoid@gmail.com',
    url='https://github.com/Equidamoid/pybus',
    ext_modules=cythonize("pybus/pybus_struct.pyx"),
    packages=setuptools.find_packages(),
    install_requires=[
        'lxml',
    ]
)
