import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="pygmdata",
    version="0.0.5",
    description="Package to interact with Grey Matter Data",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/greymatter-io/fracking",
    author="Dave Borncamp",
    author_email="engineering@greymatter.io",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        'Development Status :: 3 - Alpha',
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires='>=3.6',
    packages=["pygmdata"],
    include_package_data=True,
    install_requires=["requests>=2.25.1",
                      "requests_toolbelt>=0.9.1",
                      "Pillow>=7.2.0"],
    entry_points={
        "console_scripts": [
            "pygmdata=pygmdata.__main__:main",
        ]
    },
)
