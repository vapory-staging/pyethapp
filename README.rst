===============================
pyethapp
===============================

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/ethereum/pyethapp
   :target: https://gitter.im/ethereum/pyethapp?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://img.shields.io/travis/ethereum/pyethapp.svg
        :target: https://travis-ci.org/ethereum/pyethapp

.. image:: https://coveralls.io/repos/ethereum/pyethapp/badge.svg
        :target: https://coveralls.io/r/ethereum/pyethapp


.. image:: https://img.shields.io/pypi/v/pyethapp.svg
        :target: https://pypi.python.org/pypi/pyethapp

.. image:: https://readthedocs.org/projects/pyethapp/badge/?version=latest
        :target: https://readthedocs.org/projects/pyethapp/?badge=latest


Introduction
------------

pyethapp is the python based client implementing the Ethereum_ cryptoeconomic state machine.

Ethereum as a platform is focussed on enabling people to build new ideas using blockchain technology.

The python implementation aims to provide an easily hackable and extendable codebase.

pyethapp leverages two ethereum core components to implement the client:

* pyethereum_ - the core library, featuring the blockchain, the ethereum virtual machine, mining
* pydevp2p_ - the p2p networking library, featuring node discovery for and transport of multiple services over multiplexed and encrypted connections


.. _Ethereum: http://ethereum.org/
.. _pyethereum: https://github.com/ethereum/pyethereum
.. _pydevp2p: https://github.com/ethereum/pydevp2p


Installation and invocation
---------------------------

Install from source:

.. code:: shell

    $ git clone https://github.com/ethereum/pyethapp
    $ cd pyethapp
    $ python setup.py install

Install the latest realease from PyPI:

.. code:: shell

    $ pip install pyethapp

Show available commands and options:

.. code:: shell

    $ pyethapp


Connect to the default network (see below for more information on networks):

.. code:: shell

    $ pyethapp run


There is also Dockerfile in the repo.


Available Networks
------------------

* Frontier
* Morden

Currently there are two official networks available. The "Main Network" is
called *Frontier* and this is what the client will connect to if you start it
without any additional options.

Additionally there is the official test network Morden_ which can be used to
test new code or otherwise experiment without having to risk real money.
Use the `--profile` command line option to select the test network:

.. code:: shell

   $ pyethapp --profile morden run


.. note:: If you've previously connected to the main network you will also need
   to specify a new data directory by using the `--data-dir` option.


.. _Morden: https://github.com/ethereum/wiki/wiki/Morden

Interacting
-----------

You can interact with the client using the JSONRPC api or directly on the console.

* https://github.com/ethereum/pyethapp/wiki/The_Console
* https://github.com/ethereum/pyethapp/blob/master/pyethapp/rpc_client.py

Status
------

* Working PoC9 prototype
* interoperable with the go and cpp clients
* jsonrpc (mostly)

