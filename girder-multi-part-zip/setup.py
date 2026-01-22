from setuptools import setup, find_packages

setup(
    name='girder-multi-part-zip',
    version='0.0.1',
    description='Girder plugin for Multi-Part Zip Extraction',
    author='Josselin Duchateau',
    license='Apache 2.0',
    packages=find_packages(),
    install_requires=[
        'girder>=3.0.0',
        'girder-jobs>=3.0.0',
        'requests',
    ],
    entry_points={
        'girder.plugin': [
            'multi_part_zip = girder_multi_part_zip:MultiPartZipPlugin',
        ],
    },
    include_package_data=True,
)
