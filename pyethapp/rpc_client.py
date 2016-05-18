"""Provides a simple way of testing JSON RPC commands."""
import warnings

import logging
import json
import time

from ethereum import abi
from ethereum.keys import privtoaddr
from ethereum.transactions import Transaction
from ethereum.utils import denoms, int_to_big_endian, big_endian_to_int, normalize_address
from tinyrpc.protocols.jsonrpc import JSONRPCErrorResponse, JSONRPCSuccessResponse
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.http import HttpPostClientTransport

from pyethapp.jsonrpc import address_encoder as _address_encoder
from pyethapp.jsonrpc import (
    data_encoder, data_decoder, address_decoder, default_gasprice,
    default_startgas, quantity_encoder, quantity_decoder,
)

z_address = '\x00' * 20
log = logging.getLogger(__name__)


def address_encoder(a):
    return _address_encoder(normalize_address(a, allow_blank=True))


def block_tag_encoder(val):
    if isinstance(val, int):
        return quantity_encoder(val)
    elif val and isinstance(val, bytes):
        assert val in ('latest', 'pending')
        return data_encoder(val)
    else:
        assert not val


def topic_encoder(t):
    assert isinstance(t, (int, long))
    return data_encoder(int_to_big_endian(t))


def topic_decoder(t):
    return big_endian_to_int(data_decoder(t))


class JSONRPCClientReplyError(Exception):
    pass


class JSONRPCClient(object):
    protocol = JSONRPCProtocol()

    def __init__(self, port=4000, print_communication=True, privkey=None, sender=None):
        "specify privkey for local signing"
        self.transport = HttpPostClientTransport('http://127.0.0.1:{}'.format(port))
        self.print_communication = print_communication
        self.privkey = privkey
        self._sender = sender
        self.port = port

    def __repr__(self):
        return '<JSONRPCClient @%d>' % self.port

    @property
    def sender(self):
        if self.privkey:
            return privtoaddr(self.privkey)

        if self._sender is None:
            self._sender = self.coinbase

        return self._sender

    @property
    def coinbase(self):
        """ Return the client coinbase address. """
        return address_decoder(self.call('eth_coinbase'))

    def blocknumber(self):
        """ Return the most recent block. """
        return quantity_decoder(self.call('eth_blockNumber'))

    def nonce(self, address):
        if len(address) == 40:
            address = address.decode('hex')

        res = self.call('eth_getTransactionCount', address_encoder(address), 'pending')
        return quantity_decoder(res)

    def balance(self, account):
        """ Return the balance of the account of given address. """
        res = self.call('eth_getBalance', address_encoder(account), 'pending')
        return quantity_decoder(res)

    def gaslimit(self):
        return quantity_decoder(self.call('eth_gasLimit'))

    def lastgasprice(self):
        return quantity_decoder(self.call('eth_lastGasPrice'))

    def new_abi_contract(self, _abi, address):
        sender = self.sender or privtoaddr(self.privkey)
        return ABIContract(sender, _abi, address, self.eth_call, self.send_transaction)

    def find_block(self, condition):
        """Query all blocks one by one and return the first one for which
        `condition(block)` evaluates to `True`.
        """
        i = 0
        while True:
            block = self.call('eth_getBlockByNumber', quantity_encoder(i), True)
            if condition(block) or not block:
                return block
            i += 1

    def new_filter(self, fromBlock="", toBlock="", address=None, topics=[]):
        encoders = dict(fromBlock=block_tag_encoder, toBlock=block_tag_encoder,
                        address=address_encoder, topics=lambda x: [topic_encoder(t) for t in x])
        data = {k: encoders[k](v) for k, v in locals().items()
                if k not in ('self', 'encoders') and v is not None}
        fid = self.call('eth_newFilter', data)
        return quantity_decoder(fid)

    def filter_changes(self, fid):
        changes = self.call('eth_getFilterChanges', quantity_encoder(fid))
        if not changes:
            return None
        elif isinstance(changes, bytes):
            return data_decoder(changes)
        else:
            decoders = dict(blockHash=data_decoder,
                            transactionHash=data_decoder,
                            data=data_decoder,
                            address=address_decoder,
                            topics=lambda x: [topic_decoder(t) for t in x],
                            blockNumber=quantity_decoder,
                            logIndex=quantity_decoder,
                            transactionIndex=quantity_decoder)
            return [{k: decoders[k](v) for k, v in c.items() if v is not None} for c in changes]

    def call(self, method, *args):
        """ Do the request and returns the result.

        Args:
            method (str): The RPC method.
            args: The encoded arguments expected by the method.
                - Object arguments must be supplied as an dictionary.
                - Quantity arguments must be hex encoded starting with '0x' and
                without left zeros.
                - Data arguments must be hex encoded starting with '0x'
        """
        request = self.protocol.create_request(method, args)
        reply = self.transport.send_message(request.serialize())
        if self.print_communication:
            print json.dumps(json.loads(request.serialize()), indent=2)
            print reply

        jsonrpc_reply = self.protocol.parse_reply(reply)
        if isinstance(jsonrpc_reply, JSONRPCSuccessResponse):
            return jsonrpc_reply.result
        elif isinstance(jsonrpc_reply, JSONRPCErrorResponse):
            raise JSONRPCClientReplyError(jsonrpc_reply.error)
        else:
            raise JSONRPCClientReplyError('Unknown type of JSONRPC reply')

    __call__ = call

    def send_transaction(self, sender, to, value=0, data='', startgas=0,
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

        if not sender and not (v and r and s):
            raise ValueError('Either sender or v, r, s needs to be informed.')

        json_data = {
            'from': address_encoder(sender),
            'to': data_encoder(normalize_address(to, allow_blank=True)),
            'nonce': quantity_encoder(nonce),
            'value': quantity_encoder(value),
            'gasPrice': quantity_encoder(gasPrice),
            'gas': quantity_encoder(gas),
            'data': data_encoder(data),
            'v': quantity_encoder(v),
            'r': quantity_encoder(r),
            's': quantity_encoder(s),
        }

        res = self.call('eth_sendTransaction', json_data)

        return data_decoder(res)

    def eth_call(self, sender='', to='', value=0, data='',
                 startgas=default_startgas, gasprice=default_gasprice,
                 block_number=None):
        """ Executes a new message call immediately without creating a
        transaction on the block chain.

        Args:
            from: The address the transaction is send from.
            to: The address the transaction is directed to.
            gas (int): Gas provided for the transaction execution. eth_call
                consumes zero gas, but this parameter may be needed by some
                executions.
            gasPrice (int): gasPrice used for each paid gas.
            value (int): Integer of the value send with this transaction.
            data (bin): Hash of the method signature and encoded parameters.
                For details see Ethereum Contract ABI.
            block_number: Determines the state of ethereum used in the
                call.
        """

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
            res = self.call('eth_call', data, block_number)
        else:
            res = self.call('eth_call', data)

        return data_decoder(res)

    def poll(self, transaction_hash, confirmations=None):
        """ Wait until the `transaction_hash` is applied or reject.

        Args:
            transaction_hash (hash): Transaction hash that we are waiting for.
            confirmations (int): Quantity of block confirmations that we will
                wait for.
        """
        if transaction_hash.startswith('0x'):
            warnings.warn(
                'transaction_hash seems to be already encoded, this will result '
                'in unexpected behavior'
            )

        if len(transaction_hash) != 32:
            raise ValueError('transaction_hash length must be 32 (it might be hex encode)')

        transaction_hash = data_encoder(transaction_hash)

        pending_block = self.call('eth_getBlockByNumber', 'pending', True)
        while any(tx['hash'] == transaction_hash for tx in pending_block['transactions']):
            time.sleep(3)
            pending_block = self.call('eth_getBlockByNumber', 'pending', True)

        transaction = self.call('eth_getTransactionByHash', transaction_hash)

        if transaction is None:
            # either wrong transaction hash or the transaction was invalid
            log.error('transaction {} not found.'.format(transaction_hash))
            return

        if confirmations is None:
            return

        # this will wait for both APPLIED and REVERTED transactions
        transaction_block = quantity_decoder(transaction['blockNumber'])
        confirmation_block = transaction_block + confirmations

        block_number = self.blocknumber()
        while confirmation_block > block_number:
            time.sleep(6)
            block_number = self.blocknumber()


class ABIContract(object):
    """ Exposes the smart contract as a python object.

    This wrapper allows contracts calls to be made through a python interface,
    each function is expose as a method in the python object with the right
    amount of parameters.
    """

    def __init__(self, sender, _abi, address, call_func, transact_func):
        self._translator = abi.ContractTranslator(_abi)
        self.abi = _abi
        self.address = address = normalize_address(address)
        sender = normalize_address(sender)
        valid_kargs = set(('gasprice', 'startgas', 'value'))

        class abi_method(object):

            def __init__(this, f):
                this.f = f

            def transact(this, *args, **kargs):
                assert set(kargs.keys()).issubset(valid_kargs)
                data = self._translator.encode(this.f, args)
                txhash = transact_func(sender=sender,
                                       to=address,
                                       value=kargs.pop('value', 0),
                                       data=data,
                                       **kargs)
                return txhash

            def call(this, *args, **kargs):
                assert set(kargs.keys()).issubset(valid_kargs)
                data = self._translator.encode(this.f, args)
                res = call_func(sender=sender,
                                to=address,
                                value=kargs.pop('value', 0),
                                data=data,
                                **kargs)
                if res:
                    res = self._translator.decode(this.f, res)
                    res = res[0] if len(res) == 1 else res
                return res

            def __call__(this, *args, **kargs):
                if self._translator.function_data[this.f]['is_constant']:
                    return this.call(*args, **kargs)
                else:
                    return this.transact(*args, **kargs)

        for fname in self._translator.function_data:
            func = abi_method(fname)
            # create wrapper with signature
            signature = self._translator.function_data[fname]['signature']
            func.__doc__ = '%s(%s)' % (fname, ', '.join(('%s %s' % x) for x in signature))
            setattr(self, fname, func)
