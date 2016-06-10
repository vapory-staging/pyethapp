# -*- coding: utf8 -*-
import os
from os import path
from itertools import count

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
    data_encoder, default_gasprice, default_startgas
from pyethapp.pow_service import PoWService
from pyethapp.jsonrpc import Compilers

ethereum.keys.PBKDF2_CONSTANTS['c'] = 100  # faster key derivation
log = get_logger('test.jsonrpc')  # pylint: disable=invalid-name
SOLIDITY_AVAILABLE = 'solidity' in Compilers().compilers


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

    assert set(compiler_result.keys()) == {'test',}
    assert set(compiler_result['test'].keys()) == {'info', 'code',}
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


@pytest.fixture
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
            assert set(acct.address for acct in self.services.accounts) == set(tester.accounts[:3])

        def mine_next_block(self):
            """Mine until a valid nonce is found.

            :returns: the new head
            """
            log.debug('mining next block')
            block = self.services.chain.chain.head_candidate
            delta_nonce = 10**6
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
                'GENESIS_DIFFICULTY': 1,
                'BLOCK_DIFF_FACTOR': 2,  # greater than difficulty, thus difficulty is constant
                'GENESIS_GAS_LIMIT': 3141592,
                'GENESIS_INITIAL_ALLOC': {
                    tester.accounts[0].encode('hex'): {'balance': 10**24},
                    tester.accounts[1].encode('hex'): {'balance': 1},
                    tester.accounts[2].encode('hex'): {'balance': 10**24},
                }
            }
        },
        'jsonrpc': {'listen_port': 29873}
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
            app.services[service].stop()
        app.stop()
    request.addfinalizer(fin)

    log.debug('starting test app')
    app.start()
    return app


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
