# -*- coding: utf8 -*-
import os
from os import path
from itertools import count
import gevent
import gc
from ethereum import slogging

import pytest
import rlp
import serpent
import ethereum
import ethereum.config
import ethereum.keys
from ethereum.ethpow import mine
from ethereum import tester
from ethereum.slogging import get_logger
from devp2p.peermanager import PeerManager
import ethereum._solidity

from pyethapp.accounts import Account, AccountsService, mk_random_privkey
from pyethapp.app import EthApp
from pyethapp.config import update_config_with_defaults, get_default_config
from pyethapp.db_service import DBService
from pyethapp.eth_service import ChainService
from pyethapp.jsonrpc import Compilers, JSONRPCServer, quantity_encoder, address_encoder, data_decoder,   \
    data_encoder, default_gasprice, default_startgas, quantity_decoder
from pyethapp.profiles import PROFILES
from pyethapp.pow_service import PoWService
from ethereum import _solidity
from ethereum.abi import event_id, method_id, ContractTranslator, normalize_name
from pyethapp.rpc_client import ContractProxy
from ethereum.utils import denoms, normalize_address
from ethereum.keys import privtoaddr
import warnings
from ethereum.transactions import Transaction

ethereum.keys.PBKDF2_CONSTANTS['c'] = 100  # faster key derivation
log = get_logger('test.jsonrpc')  # pylint: disable=invalid-name
SOLIDITY_AVAILABLE = False # 'solidity' in Compilers().compilers


# EVM code corresponding to the following solidity code:
#
#     contract LogTest {
#         event Log();
#
#         function () {
#             Log();
#         }
#     }
#
# (compiled with online Solidity compiler at https://chriseth.github.io/browser-solidity/ version
# 0.1.1-34172c3b/RelWithDebInfo-Emscripten/clang/int)
LOG_EVM = (
    '606060405260448060116000396000f30060606040523615600d57600d565b60425b7f5e7df75d54'
    'e493185612379c616118a4c9ac802de621b010c96f74d22df4b30a60405180905060405180910390'
    'a15b565b00'
).decode('hex')


def test_externally():
    # The results of the external rpc-tests are not evaluated as:
    #  1) the Whisper protocol is not implemented and its tests fail;
    #  2) the eth_accounts method should be skipped;
    #  3) the eth_getFilterLogs fails due to the invalid test data;
    """    os.system('''
        git clone https://github.com/ethereum/rpc-tests;
        cd rpc-tests;
        git submodule update --init --recursive;
        npm install;
        rm -rf /tmp/rpctests;
        pyethapp -d /tmp/rpctests -l :info,eth.chainservice:debug,jsonrpc:debug -c jsonrpc.listen_port=8081 -c p2p.max_peers=0 -c p2p.min_peers=0 blocktest lib/tests/BlockchainTests/bcRPC_API_Test.json RPC_API_Test & sleep 60 && make test;
    ''')
    """

@pytest.mark.skipif(not SOLIDITY_AVAILABLE, reason='solidity compiler not available')
def test_compile_solidity():
    with open(path.join(path.dirname(__file__), 'contracts', 'multiply.sol')) as handler:
        solidity_code = handler.read()

    solidity = ethereum._solidity.get_solidity()  # pylint: disable=protected-access

    abi = solidity.mk_full_signature(solidity_code)
    code = data_encoder(solidity.compile(solidity_code))

    info = {
        'abiDefinition': abi,
        'compilerVersion': '0',
        'developerDoc': {
            'methods': None,
        },
        'language': 'Solidity',
        'languageVersion': '0',
        'source': solidity_code,
        'userDoc': {
            'methods': None,
        },
    }
    test_result = {
        'test': {
            'code': code,
            'info': info,
        }
    }
    compiler_result = Compilers().compileSolidity(solidity_code)

    assert set(compiler_result.keys()) == {'test', }
    assert set(compiler_result['test'].keys()) == {'info', 'code', }
    assert set(compiler_result['test']['info']) == {
        'abiDefinition',
        'compilerVersion',
        'developerDoc',
        'language',
        'languageVersion',
        'source',
        'userDoc',
    }

    assert test_result['test']['code'] == compiler_result['test']['code']

    compiler_info = dict(compiler_result['test']['info'])

    compiler_info.pop('compilerVersion')
    info.pop('compilerVersion')

    assert compiler_info['abiDefinition'] == info['abiDefinition']


@pytest.fixture(params=[0,
    PROFILES['testnet']['eth']['block']['ACCOUNT_INITIAL_NONCE']])
def test_app(request, tmpdir):

    class TestApp(EthApp):

        def start(self):
            super(TestApp, self).start()
            log.debug('adding test accounts')
            # high balance account
            self.services.accounts.add_account(Account.new('', tester.keys[0]), store=False)
            # low balance account
            self.services.accounts.add_account(Account.new('', tester.keys[1]), store=False)
            # locked account
            locked_account = Account.new('', tester.keys[2])
            locked_account.lock()
            self.services.accounts.add_account(locked_account, store=False)
            self.privkey = None
            assert set(acct.address for acct in self.services.accounts) == set(tester.accounts[:3])

        def mine_next_block(self):
            """Mine until a valid nonce is found.

            :returns: the new head
            """
            log.debug('mining next block')
            block = self.services.chain.chain.head_candidate
            delta_nonce = 10 ** 6
            for start_nonce in count(0, delta_nonce):
                bin_nonce, mixhash = mine(block.number, block.difficulty, block.mining_hash,
                                          start_nonce=start_nonce, rounds=delta_nonce)
                if bin_nonce:
                    break
            self.services.pow.recv_found_nonce(bin_nonce, mixhash, block.mining_hash)
            log.debug('block mined')
            assert self.services.chain.chain.head.difficulty == 1
            return self.services.chain.chain.head

        def rpc_request(self, method, *args):
            """Simulate an incoming JSON RPC request and return the result.

            Example::

                >>> assert test_app.rpc_request('eth_getBalance', '0x' + 'ff' * 20) == '0x0'

            """
            log.debug('simulating rpc request', method=method)
            method = self.services.jsonrpc.dispatcher.get_method(method)
            res = method(*args)
            log.debug('got response', response=res)
            return res

        def eth_call(self, sender='', to='', value=0, data='',
                 startgas=default_startgas, gasprice=default_gasprice,
                 block_number=None):

            json_data = dict()

            if sender is not None:
                json_data['from'] = address_encoder(sender)

            if to is not None:
                json_data['to'] = data_encoder(to)

            if value is not None:
                json_data['value'] = quantity_encoder(value)

            if gasprice is not None:
                json_data['gasPrice'] = quantity_encoder(gasprice)

            if startgas is not None:
                json_data['gas'] = quantity_encoder(startgas)

            if data is not None:
                json_data['data'] = data_encoder(data)

            if block_number is not None:
                res = self.rpc_request('eth_call', json_data, block_number)
            else:
                res = self.rpc_request('eth_call', json_data)

            return data_decoder(res)

        def eth_transact(self, sender, to, value=0, data='', startgas=0,
                         gasprice=10 * denoms.szabo, nonce=None):
            """ Helper to send signed messages.

            This method will use the `privkey` provided in the constructor to
            locally sign the transaction. This requires an extended server
            implementation that accepts the variables v, r, and s.
            """

            if not self.privkey and not sender:
                raise ValueError('Either privkey or sender needs to be supplied.')

            if self.privkey and not sender:
                sender = privtoaddr(self.privkey)

                if nonce is None:
                    nonce = self.nonce(sender)
            elif self.privkey:
                if sender != privtoaddr(self.privkey):
                    raise ValueError('sender for a different privkey.')

                if nonce is None:
                    nonce = self.nonce(sender)
            else:
                if nonce is None:
                    nonce = 0

            if not startgas:
                startgas = self.gaslimit() - 1

            tx = Transaction(nonce, gasprice, startgas, to=to, value=value, data=data)

            if self.privkey:
                # add the fields v, r and s
                tx.sign(self.privkey)

            tx_dict = tx.to_dict()

            # rename the fields to match the eth_sendTransaction signature
            tx_dict.pop('hash')
            tx_dict['sender'] = sender
            tx_dict['gasPrice'] = tx_dict.pop('gasprice')
            tx_dict['gas'] = tx_dict.pop('startgas')

            res = self.eth_sendTransaction(**tx_dict)
            assert len(res) in (20, 32)
            return res.encode('hex')

        def eth_sendTransaction(self, nonce=None, sender='', to='', value=0, data='',
                                gasPrice=default_gasprice, gas=default_startgas,
                                v=None, r=None, s=None):
            """ Creates new message call transaction or a contract creation, if the
            data field contains code.

            Note:
                The support for local signing through the variables v,r,s is not
                part of the standard spec, a extended server is required.

            Args:
                from (address): The 20 bytes address the transaction is send from.
                to (address): DATA, 20 Bytes - (optional when creating new
                    contract) The address the transaction is directed to.
                gas (int): Gas provided for the transaction execution. It will
                    return unused gas.
                gasPrice (int): gasPrice used for each paid gas.
                value (int): Value send with this transaction.
                data (bin): The compiled code of a contract OR the hash of the
                    invoked method signature and encoded parameters.
                nonce (int): This allows to overwrite your own pending transactions
                    that use the same nonce.
            """

            if to == '' and data.isalnum():
                warnings.warn(
                    'Verify that the data parameter is _not_ hex encoded, if this is the case '
                    'the data will be double encoded and result in unexpected '
                    'behavior.'
                )

            if to == '0' * 40:
                warnings.warn('For contract creating the empty string must be used.')

            json_data = {
                'to': data_encoder(normalize_address(to, allow_blank=True)),
                'value': quantity_encoder(value),
                'gasPrice': quantity_encoder(gasPrice),
                'gas': quantity_encoder(gas),
                'data': data_encoder(data),
            }

            if not sender and not (v and r and s):
                raise ValueError('Either sender or v, r, s needs to be informed.')

            if sender is not None:
                json_data['from'] = address_encoder(sender)

            if v and r and s:
                json_data['v'] = quantity_encoder(v)
                json_data['r'] = quantity_encoder(r)
                json_data['s'] = quantity_encoder(s)

            if nonce is not None:
                json_data['nonce'] = quantity_encoder(nonce)

            res = self.rpc_request('eth_sendTransaction', json_data)

            return data_decoder(res)

        def gaslimit(self):
            return quantity_decoder(self.rpc_request('eth_gasLimit'))

    config = {
        'data_dir': str(tmpdir),
        'db': {'implementation': 'EphemDB'},
        'pow': {'activated': False},
        'p2p': {
            'min_peers': 0,
            'max_peers': 0,
            'listen_port': 29873
        },
        'node': {'privkey_hex': mk_random_privkey().encode('hex')},
        'discovery': {
            'boostrap_nodes': [],
            'listen_port': 29873
        },
        'eth': {
            'block': {  # reduced difficulty, increased gas limit, allocations to test accounts
                'ACCOUNT_INITIAL_NONCE': request.param,
                'GENESIS_DIFFICULTY': 1,
                'BLOCK_DIFF_FACTOR': 2,  # greater than difficulty, thus difficulty is constant
                 'GENESIS_GAS_LIMIT': 3141592,
                'GENESIS_INITIAL_ALLOC': {
                    tester.accounts[0].encode('hex'): {'balance': 10 ** 24},
                    tester.accounts[1].encode('hex'): {'balance': 1},
                    tester.accounts[2].encode('hex'): {'balance': 10 ** 24},
                }
            }
        },
        'jsonrpc': {'listen_port': 4488, 'listen_host': '127.0.0.1'}
    }
    services = [DBService, AccountsService, PeerManager, ChainService, PoWService, JSONRPCServer]
    update_config_with_defaults(config, get_default_config([TestApp] + services))
    update_config_with_defaults(config, {'eth': {'block': ethereum.config.default_config}})
    app = TestApp(config)
    for service in services:
        service.register_with_app(app)

    def fin():
        log.debug('stopping test app')
        for service in app.services:
            gevent.sleep(.1)
            try:
                app.services[service].stop()
            except Exception as e:
                log.DEV(str(e), exc_info=e)
                pass
        app.stop()
        gevent.killall(task for task in gc.get_objects() if isinstance(task, gevent.Greenlet))

    request.addfinalizer(fin)

    log.debug('starting test app')
    app.start()
    return app


def get_event(full_abi, event_name):
    for description in full_abi:
        name = description.get('name')

        # skip constructors
        if name is None:
            continue

        normalized_name = normalize_name(name)

        if normalized_name == event_name:
            return description


def get_eventname_types(event_description):
    if 'name' not in event_description:
        raise ValueError('Not an event description, missing the name.')

    name = normalize_name(event_description['name'])
    encode_types = [
        element['type']
        for element in event_description['inputs']
    ]
    return name, encode_types


sample_sol_code = """

contract SampleContract {
    uint256 balance1 = 0;
    uint256 balance2 = 0;
    uint256 balance3 = 0;
    event Event1(address bidder, uint256 indexed amount);
    event Event2(address bidder, uint256 indexed amount1, uint256 indexed  amount2);
    event Event3(address bidder, uint256 indexed amount1, uint256 indexed amount2, uint256 indexed amount3);

    function trigger1(uint256 amount)
    {
        balance1 += amount;
        Event1(msg.sender, balance1);
    }
    function trigger2(uint256 amount) {
        balance2 += amount;
        Event2(msg.sender, balance1, balance2);
    }
    function trigger3(uint256 amount) {
        balance3 += amount;
        Event3(msg.sender, balance1, balance2, balance3);
    }
    function getbalance1()
     constant
     returns (uint256)
    {
        return balance1;
    }
    function getbalance2()
     constant
     returns (uint256)
    {
        return balance2;
    }
    function getbalance3()
     constant
     returns (uint256)
    {
        return balance3;
    }
}

"""


def test_logfilters_topics(test_app):
    # slogging.configure(':trace')
    sample_compiled = _solidity.compile_code(
    sample_sol_code,
    combined='bin,abi',
    )

    theabi = sample_compiled['SampleContract']['abi']
    theevm = sample_compiled['SampleContract']['bin_hex']

    sender_address = test_app.services.accounts.unlocked_accounts[0].address
    sender = address_encoder(sender_address)

    event1 = get_event(theabi, 'Event1')
    event2 = get_event(theabi, 'Event2')
    event3 = get_event(theabi, 'Event3')
    event1_id = event_id(*get_eventname_types(event1))
    event2_id = event_id(*get_eventname_types(event2))
    event3_id = event_id(*get_eventname_types(event3))

    test_app.mine_next_block()  # start with a fresh block

    n0 = test_app.services.chain.chain.head.number
    assert n0 == 1

    contract_creation = {
        'from': sender,
        'data': '0x'+theevm,
        'gas': quantity_encoder(1000000)
    }

    tx_hash = test_app.rpc_request('eth_sendTransaction', contract_creation)
    test_app.mine_next_block()
    receipt = test_app.rpc_request('eth_getTransactionReceipt', tx_hash)
    contract_address = receipt['contractAddress']

    sample_contract = ContractProxy(sender_address, theabi, contract_address,
                                    test_app.eth_call, test_app.eth_transact)

    topic1 = hex(event1_id).rstrip("L")
    topic2 = hex(event2_id).rstrip("L")
    topic3 = hex(event3_id).rstrip("L")
    topica, topicb, topicc = \
        '0x0000000000000000000000000000000000000000000000000000000000000001',\
        '0x0000000000000000000000000000000000000000000000000000000000000064',\
        '0x00000000000000000000000000000000000000000000000000000000000003e8'
    topic_filter_1 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic1]
    })
    topic_filter_2 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic2]
    })
    topic_filter_3 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic3]
    })
    topic_filter_4 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic1, topica]
    })

    topic_filter_5 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic2, topica, topicb]
    })
    topic_filter_6 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic3, topica, topicb, topicc]
    })
    topic_filter_7 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topica, topicb, topicc]
    })
    topic_filter_8 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic3, topica, topicb]
    })
    topic_filter_9 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topicc, topicb, topica, topic3]
    })
    topic_filter_10 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topicb, topicc, topica, topic3]
    })
    topic_filter_11 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic2, topica]
    })
    topic_filter_12 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic3, topica]
    })
    topic_filter_13 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topica, topicb]
    })
    topic_filter_14 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic2, [topica, topicb]]
    })
    topic_filter_15 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [[topic1, topic2], topica]
    })
    topic_filter_16 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [[topic1, topic2, topic3]]
    })
    topic_filter_17 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [[topic1, topic2, topic3, topica, topicb, topicc]]
    })
    topic_filter_18 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic2, topica, topicb, [topic2, topica, topicb]]
    })
    topic_filter_19 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [topic1, topica, topicb]
    })
    topic_filter_20 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [[topic1, topic2], [topica, topicb], [topica, topicb]]
    })
    topic_filter_21 = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 0,
        'toBlock': 'pending',
        'topics': [[topic2, topic3], [topica, topicb], [topica, topicb]]
    })

    thecode = test_app.rpc_request('eth_getCode', address_encoder(sample_contract.address))
    assert len(thecode) > 2

    sample_contract.trigger1(1)
    test_app.mine_next_block()
    sample_contract.trigger2(100)
    test_app.mine_next_block()
    sample_contract.trigger3(1000)
    test_app.mine_next_block()

    tl1 = test_app.rpc_request('eth_getFilterChanges', topic_filter_1)
    assert len(tl1) == 1
    tl2 = test_app.rpc_request('eth_getFilterChanges', topic_filter_2)
    assert len(tl2) == 1
    tl3 = test_app.rpc_request('eth_getFilterChanges', topic_filter_3)
    assert len(tl3) == 1
    tl4 = test_app.rpc_request('eth_getFilterChanges', topic_filter_4)
    assert len(tl4) == 1
    tl5 = test_app.rpc_request('eth_getFilterChanges', topic_filter_5)
    assert len(tl5) == 1
    tl6 = test_app.rpc_request('eth_getFilterChanges', topic_filter_6)
    assert len(tl6) == 1
    tl7 = test_app.rpc_request('eth_getFilterChanges', topic_filter_7)
    assert len(tl7) == 0
    tl8 = test_app.rpc_request('eth_getFilterChanges', topic_filter_8)
    assert len(tl8) == 1
    tl9 = test_app.rpc_request('eth_getFilterChanges', topic_filter_9)
    assert len(tl9) == 0
    tl10 = test_app.rpc_request('eth_getFilterChanges', topic_filter_10)
    assert len(tl10) == 0
    tl11 = test_app.rpc_request('eth_getFilterChanges', topic_filter_11)
    assert len(tl11) == 1
    tl12 = test_app.rpc_request('eth_getFilterChanges', topic_filter_12)
    assert len(tl12) == 1
    tl13 = test_app.rpc_request('eth_getFilterChanges', topic_filter_13)
    assert len(tl13) == 0
    tl14 = test_app.rpc_request('eth_getFilterChanges', topic_filter_14)
    assert len(tl14) == 1
    tl15 = test_app.rpc_request('eth_getFilterChanges', topic_filter_15)
    assert len(tl15) == 2
    tl16 = test_app.rpc_request('eth_getFilterChanges', topic_filter_16)
    assert len(tl16) == 3
    tl17 = test_app.rpc_request('eth_getFilterChanges', topic_filter_17)
    assert len(tl17) == 3
    tl18 = test_app.rpc_request('eth_getFilterChanges', topic_filter_18)
    assert len(tl18) == 0
    tl19 = test_app.rpc_request('eth_getFilterChanges', topic_filter_19)
    assert len(tl19) == 0
    tl20 = test_app.rpc_request('eth_getFilterChanges', topic_filter_20)
    assert len(tl20) == 1
    tl21 = test_app.rpc_request('eth_getFilterChanges', topic_filter_21)
    assert len(tl21) == 2


def test_send_transaction(test_app):
    chain = test_app.services.chain.chain
    assert chain.head_candidate.get_balance('\xff' * 20) == 0
    sender = test_app.services.accounts.unlocked_accounts[0].address
    assert chain.head_candidate.get_balance(sender) > 0
    tx = {
        'from': address_encoder(sender),
        'to': address_encoder('\xff' * 20),
        'value': quantity_encoder(1)
    }
    tx_hash = data_decoder(test_app.rpc_request('eth_sendTransaction', tx))
    assert tx_hash == chain.head_candidate.get_transaction(0).hash
    assert chain.head_candidate.get_balance('\xff' * 20) == 1
    test_app.mine_next_block()
    assert tx_hash == chain.head.get_transaction(0).hash
    assert chain.head.get_balance('\xff' * 20) == 1

    # send transactions from account which can't pay gas
    tx['from'] = address_encoder(test_app.services.accounts.unlocked_accounts[1].address)
    tx_hash = data_decoder(test_app.rpc_request('eth_sendTransaction', tx))
    assert chain.head_candidate.get_transactions() == []


def test_send_transaction_with_contract(test_app):
    serpent_code = '''
def main(a,b):
    return(a ^ b)
'''
    tx_to = b''
    evm_code = serpent.compile(serpent_code)
    chain = test_app.services.chain.chain
    assert chain.head_candidate.get_balance(tx_to) == 0
    sender = test_app.services.accounts.unlocked_accounts[0].address
    assert chain.head_candidate.get_balance(sender) > 0
    tx = {
        'from': address_encoder(sender),
        'to': address_encoder(tx_to),
        'data': evm_code.encode('hex')
    }
    data_decoder(test_app.rpc_request('eth_sendTransaction', tx))
    creates = chain.head_candidate.get_transaction(0).creates

    code = chain.head_candidate.account_to_dict(creates)['code']
    assert len(code) > 2
    assert code != '0x'

    test_app.mine_next_block()

    creates = chain.head.get_transaction(0).creates
    code = chain.head.account_to_dict(creates)['code']
    assert len(code) > 2
    assert code != '0x'


def test_send_raw_transaction_with_contract(test_app):
    serpent_code = '''
def main(a,b):
    return(a ^ b)
'''
    tx_to = b''
    evm_code = serpent.compile(serpent_code)
    chain = test_app.services.chain.chain
    assert chain.head_candidate.get_balance(tx_to) == 0
    sender = test_app.services.accounts.unlocked_accounts[0].address
    assert chain.head_candidate.get_balance(sender) > 0
    nonce = chain.head_candidate.get_nonce(sender)
    tx = ethereum.transactions.Transaction(nonce, default_gasprice, default_startgas, tx_to, 0, evm_code, 0, 0, 0)
    test_app.services.accounts.sign_tx(sender, tx)
    raw_transaction = data_encoder(rlp.codec.encode(tx, ethereum.transactions.Transaction))
    data_decoder(test_app.rpc_request('eth_sendRawTransaction', raw_transaction))
    creates = chain.head_candidate.get_transaction(0).creates

    code = chain.head_candidate.account_to_dict(creates)['code']
    assert len(code) > 2
    assert code != '0x'

    test_app.mine_next_block()

    creates = chain.head.get_transaction(0).creates
    code = chain.head.account_to_dict(creates)['code']
    assert len(code) > 2
    assert code != '0x'


def test_pending_transaction_filter(test_app):
    filter_id = test_app.rpc_request('eth_newPendingTransactionFilter')
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == []
    tx = {
        'from': address_encoder(test_app.services.accounts.unlocked_accounts[0].address),
        'to': address_encoder('\xff' * 20)
    }

    def test_sequence(s):
        tx_hashes = []
        for c in s:
            if c == 't':
                tx_hashes.append(test_app.rpc_request('eth_sendTransaction', tx))
            elif c == 'b':
                test_app.mine_next_block()
            else:
                assert False
        assert test_app.rpc_request('eth_getFilterChanges', filter_id) == tx_hashes
        assert test_app.rpc_request('eth_getFilterChanges', filter_id) == []

    sequences = [
        't',
        'b',
        'ttt',
        'tbt',
        'ttbttt',
        'bttbtttbt',
        'bttbtttbttbb',
    ]
    map(test_sequence, sequences)


def test_new_block_filter(test_app):
    filter_id = test_app.rpc_request('eth_newBlockFilter')
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == []
    h = test_app.mine_next_block().hash
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == [data_encoder(h)]
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == []
    hashes = [data_encoder(test_app.mine_next_block().hash) for i in range(3)]
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == hashes
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == []
    assert test_app.rpc_request('eth_getFilterChanges', filter_id) == []


def test_get_logs(test_app):
    test_app.mine_next_block()  # start with a fresh block
    n0 = test_app.services.chain.chain.head.number
    sender = address_encoder(test_app.services.accounts.unlocked_accounts[0].address)
    contract_creation = {
        'from': sender,
        'data': data_encoder(LOG_EVM)
    }
    tx_hash = test_app.rpc_request('eth_sendTransaction', contract_creation)
    test_app.mine_next_block()
    receipt = test_app.rpc_request('eth_getTransactionReceipt', tx_hash)
    contract_address = receipt['contractAddress']
    tx = {
        'from': sender,
        'to': contract_address
    }

    # single log in pending block
    test_app.rpc_request('eth_sendTransaction', tx)
    logs1 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': 'pending',
        'toBlock': 'pending'
    })
    assert len(logs1) == 1
    assert logs1[0]['type'] == 'pending'
    assert logs1[0]['logIndex'] is None
    assert logs1[0]['transactionIndex'] is None
    assert logs1[0]['transactionHash'] is None
    assert logs1[0]['blockHash'] is None
    assert logs1[0]['blockNumber'] is None
    assert logs1[0]['address'] == contract_address

    logs2 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': 'pending',
        'toBlock': 'pending'
    })
    assert logs2 == logs1

    # same log, but now mined in head
    test_app.mine_next_block()
    logs3 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': 'latest',
        'toBlock': 'latest'
    })
    assert len(logs3) == 1
    assert logs3[0]['type'] == 'mined'
    assert logs3[0]['logIndex'] == '0x0'
    assert logs3[0]['transactionIndex'] == '0x0'
    assert logs3[0]['blockHash'] == data_encoder(test_app.services.chain.chain.head.hash)
    assert logs3[0]['blockNumber'] == quantity_encoder(test_app.services.chain.chain.head.number)
    assert logs3[0]['address'] == contract_address

    # another log in pending block
    test_app.rpc_request('eth_sendTransaction', tx)
    logs4 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': 'latest',
        'toBlock': 'pending'
    })
    assert logs4 == [logs1[0], logs3[0]] or logs4 == [logs3[0], logs1[0]]

    # two logs in pending block
    test_app.rpc_request('eth_sendTransaction', tx)
    logs5 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': 'pending',
        'toBlock': 'pending'
    })
    assert len(logs5) == 2
    assert logs5[0] == logs5[1] == logs1[0]

    # two logs in head
    test_app.mine_next_block()
    logs6 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': 'latest',
        'toBlock': 'pending'
    })
    for log in logs6:
        assert log['type'] == 'mined'
        assert log['logIndex'] == '0x0'
        assert log['blockHash'] == data_encoder(test_app.services.chain.chain.head.hash)
        assert log['blockNumber'] == quantity_encoder(test_app.services.chain.chain.head.number)
        assert log['address'] == contract_address
    assert sorted([log['transactionIndex'] for log in logs6]) == ['0x0', '0x1']

    # everything together with another log in pending block
    test_app.rpc_request('eth_sendTransaction', tx)
    logs7 = test_app.rpc_request('eth_getLogs', {
        'fromBlock': quantity_encoder(n0),
        'toBlock': 'pending'
    })
    assert sorted(logs7) == sorted(logs3 + logs6 + logs1)


def test_get_filter_changes(test_app):
    test_app.mine_next_block()  # start with a fresh block
    n0 = test_app.services.chain.chain.head.number
    assert n0 == 1
    sender = address_encoder(test_app.services.accounts.unlocked_accounts[0].address)
    contract_creation = {
        'from': sender,
        'data': data_encoder(LOG_EVM)
    }
    tx_hash = test_app.rpc_request('eth_sendTransaction', contract_creation)
    test_app.mine_next_block()
    receipt = test_app.rpc_request('eth_getTransactionReceipt', tx_hash)
    contract_address = receipt['contractAddress']
    tx = {
        'from': sender,
        'to': contract_address
    }

    pending_filter_id = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 'pending',
        'toBlock': 'pending'
    })
    latest_filter_id = test_app.rpc_request('eth_newFilter', {
        'fromBlock': 'latest',
        'toBlock': 'latest'
    })

    tx_hashes = []
    logs = []

    # tx in pending block
    tx_hashes.append(test_app.rpc_request('eth_sendTransaction', tx))
    logs.append(test_app.rpc_request('eth_getFilterChanges', pending_filter_id))
    assert len(logs[-1]) == 1
    assert logs[-1][0]['type'] == 'pending'
    assert logs[-1][0]['logIndex'] is None
    assert logs[-1][0]['transactionIndex'] is None
    assert logs[-1][0]['transactionHash'] is None
    assert logs[-1][0]['blockHash'] is None
    assert logs[-1][0]['blockNumber'] is None
    assert logs[-1][0]['address'] == contract_address
    pending_log = logs[-1][0]

    logs.append(test_app.rpc_request('eth_getFilterChanges', pending_filter_id))
    assert logs[-1] == []

    logs.append(test_app.rpc_request('eth_getFilterChanges', latest_filter_id))
    assert logs[-1] == []

    test_app.mine_next_block()
    logs.append(test_app.rpc_request('eth_getFilterChanges', latest_filter_id))
    assert len(logs[-1]) == 1  # log from before, but now mined
    assert logs[-1][0]['type'] == 'mined'
    assert logs[-1][0]['logIndex'] == '0x0'
    assert logs[-1][0]['transactionIndex'] == '0x0'
    assert logs[-1][0]['transactionHash'] == tx_hashes[-1]
    assert logs[-1][0]['blockHash'] == data_encoder(test_app.services.chain.chain.head.hash)
    assert logs[-1][0]['blockNumber'] == quantity_encoder(test_app.services.chain.chain.head.number)
    assert logs[-1][0]['address'] == contract_address
    logs_in_range = [logs[-1][0]]

    # send tx and mine block
    tx_hashes.append(test_app.rpc_request('eth_sendTransaction', tx))
    test_app.mine_next_block()
    logs.append(test_app.rpc_request('eth_getFilterChanges', pending_filter_id))
    assert len(logs[-1]) == 1
    assert logs[-1][0]['type'] == 'mined'
    assert logs[-1][0]['logIndex'] == '0x0'
    assert logs[-1][0]['transactionIndex'] == '0x0'
    assert logs[-1][0]['transactionHash'] == tx_hashes[-1]
    assert logs[-1][0]['blockHash'] == data_encoder(test_app.services.chain.chain.head.hash)
    assert logs[-1][0]['blockNumber'] == quantity_encoder(test_app.services.chain.chain.head.number)
    assert logs[-1][0]['address'] == contract_address
    logs_in_range.append(logs[-1][0])

    logs.append(test_app.rpc_request('eth_getFilterChanges', latest_filter_id))
    assert logs[-1] == logs[-2]  # latest and pending filter see same (mined) log

    logs.append(test_app.rpc_request('eth_getFilterChanges', latest_filter_id))
    assert logs[-1] == []

    test_app.mine_next_block()
    logs.append(test_app.rpc_request('eth_getFilterChanges', pending_filter_id))
    assert logs[-1] == []

    range_filter_id = test_app.rpc_request('eth_newFilter', {
        'fromBlock': quantity_encoder(test_app.services.chain.chain.head.number - 3),
        'toBlock': 'pending'
    })
    tx_hashes.append(test_app.rpc_request('eth_sendTransaction', tx))
    logs.append(test_app.rpc_request('eth_getFilterChanges', range_filter_id))
    assert sorted(logs[-1]) == sorted(logs_in_range + [pending_log])




def test_eth_nonce(test_app):
    """
    Test for the spec extension `eth_nonce`, which is used by
    the spec extended `eth_sendTransaction` with local signing.
    :param test_app:
    :return:
    """
    assert test_app.rpc_request('eth_getTransactionCount', address_encoder(tester.accounts[0])) == '0x0'
    assert (
        int(test_app.rpc_request('eth_nonce', address_encoder(tester.accounts[0])), 16) ==
        test_app.config['eth']['block']['ACCOUNT_INITIAL_NONCE'])

    assert test_app.rpc_request('eth_sendTransaction', dict(sender=address_encoder(tester.accounts[0]), to=''))
    assert test_app.rpc_request('eth_getTransactionCount', address_encoder(tester.accounts[0])) == '0x1'
    assert (
        int(test_app.rpc_request('eth_nonce', address_encoder(tester.accounts[0])), 16) ==
        test_app.config['eth']['block']['ACCOUNT_INITIAL_NONCE'] + 1)
    assert test_app.rpc_request('eth_sendTransaction', dict(sender=address_encoder(tester.accounts[0]), to=''))
    assert test_app.rpc_request('eth_getTransactionCount', address_encoder(tester.accounts[0])) == '0x2'
    test_app.mine_next_block()
    assert test_app.services.chain.chain.head.number == 1
    assert (
        int(test_app.rpc_request('eth_nonce', address_encoder(tester.accounts[0])), 16) ==
        test_app.config['eth']['block']['ACCOUNT_INITIAL_NONCE'] + 2)
