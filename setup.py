#!/usr/bin/env python
# -*- coding: utf-8 -*-


from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import os
        # The results of the rpc-tests are not evaluated as the Whisper protocol is not implemented and its tests fail
        os.system('''
        git clone https://github.com/ethereum/rpc-tests ;
        cd rpc-tests;
        git submodule update --init --recursive;
        rm -rf /tmp/rpctests ; pyethapp -d /tmp/rpctests -l :info,eth.chainservice:debug,jsonrpc:debug -c jsonrpc.listen_port=8081 -c p2p.max_peers=0 -c p2p.min_peers=0 blocktest lib/tests/BlockchainTests/bcRPC_API_Test.json RPC_API_Test & sleep 60 && make test;
        ''')
        import pytest
        errno = pytest.main(self.test_args)
        raise SystemExit(errno)


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read().replace('.. :changelog:', '')


install_requires = set(x.strip() for x in open('requirements.txt'))
install_requires_replacements = {
    'https://github.com/ethereum/ethash/tarball/master#egg=pyethash': 'pyethash'}

install_requires = [install_requires_replacements.get(r, r) for r in install_requires]
test_requirements = ['ethereum-serpent>=1.8.1', 'pytest']

# *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
# see: https://github.com/ethereum/pyethapp/wiki/Development:-Versions-and-Releases
version = '1.1.2'

setup(
    name='pyethapp',
    version=version,
    description="Python Ethereum Client",
    long_description=readme + '\n\n' + history,
    author="HeikoHeiko",
    author_email='heiko@ethdev.com',
    url='https://github.com/ethereum/pyethapp',
    packages=[
        'pyethapp',
    ],
    package_data={
        'pyethapp': ['genesisdata/*.json']
    },
    license="BSD",
    zip_safe=False,
    keywords='pyethapp',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
    ],
    cmdclass={'test': PyTest},
    install_requires=install_requires,
    tests_require=test_requirements,
    entry_points='''
    [console_scripts]
    pyethapp=pyethapp.app:app
    '''
)
