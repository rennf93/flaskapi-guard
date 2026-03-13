from setuptools import find_packages, setup

setup(
    packages=find_packages(include=["flaskapi_guard", "flaskapi_guard.*"]),
    include_package_data=True,
    package_data={
        "flaskapi_guard": ["py.typed"],
    },
)
