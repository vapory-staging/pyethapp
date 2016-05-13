"""Provides a simple way of testing JSON RPC commands."""
import warnings

import json
from ethereum import abi
from ethereum.keys import privtoaddr
from ethereum.transactions import Transaction
from ethereum.utils import denoms, int_to_big_endian, big_endian_to_int, normalize_address
from pyethapp.jsonrpc import address_encoder as _address_encoder
from pyethapp.jsonrpc import data_encoder, data_decoder, address_decoder
from pyethapp.jsonrpc import default_gasprice, default_startgas
from pyethapp.jsonrpc import quantity_encoder, quantity_decoder
from tinyrpc.protocols.jsonrpc import JSONRPCErrorResponse, JSONRPCSuccessResponse
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.http import HttpPostClientTransport

z_address = '\x00' * 20


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

    def call(self, method, *args):
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

    def eth_sendTransaction(self, nonce=None, sender='', to='', value=0, data='',
                            gasPrice=default_gasprice, gas=default_startgas,
                            v=None, r=None, s=None):

        if data.isalnum():
            warnings.warn(
                'Verify that the data parameter is _not_ hex encoded, if this is the case '
                'the data will be double encoded and result in unexpected '
                'behavior.'
            )

        to = normalize_address(to, allow_blank=True)
        encoders = dict(nonce=quantity_encoder, sender=address_encoder, to=data_encoder,
                        value=quantity_encoder, gasPrice=quantity_encoder,
                        gas=quantity_encoder, data=data_encoder,
                        v=quantity_encoder, r=quantity_encoder, s=quantity_encoder)
        data = {k: encoders[k](v) for k, v in locals().items()
                if k not in ('self', 'encoders') and v is not None}
        data['from'] = data.pop('sender')
        assert data.get('from') or (v and r and s)
        res = self.call('eth_sendTransaction', data)
        return data_decoder(res)

    def eth_call(self, sender='', to='', value=0, data='',
                 startgas=default_startgas, gasprice=default_gasprice):
        "call on pending block"
        encoders = dict(sender=address_encoder, to=data_encoder,
                        value=quantity_encoder, gasprice=quantity_encoder,
                        startgas=quantity_encoder, data=data_encoder)
        data = {k: encoders[k](v) for k, v in locals().items()
                if k not in ('self', 'encoders') and v is not None}
        for k, v in dict(gasprice='gasPrice', startgas='gas', sender='from').items():
            data[v] = data.pop(k)
        res = self.call('eth_call', data)
        return data_decoder(res)

    def blocknumber(self):
        return quantity_decoder(self.call('eth_blockNumber'))

    def nonce(self, address):
        if len(address) == 40:
            address = address.decode('hex')
        return quantity_decoder(
            self.call('eth_getTransactionCount', address_encoder(address), 'pending'))

    @property
    def coinbase(self):
        return address_decoder(self.call('eth_coinbase'))

    def balance(self, account):
        b = quantity_decoder(
            self.call('eth_getBalance', address_encoder(account), 'pending'))
        return b

    def gaslimit(self):
        return quantity_decoder(self.call('eth_gasLimit'))

    def lastgasprice(self):
        return quantity_decoder(self.call('eth_lastGasPrice'))

    def send_transaction(self, sender, to, value=0, data='', startgas=0,
                         gasprice=10 * denoms.szabo, nonce=None):
        "can send a locally signed transaction if privkey is given"
        assert self.privkey or sender
        if self.privkey:
            _sender = sender
            sender = privtoaddr(self.privkey)
            assert sender == _sender
            # fetch nonce
            nonce = nonce if nonce is not None else self.nonce(sender)
        if nonce is None:
            nonce = 0


        assert sender
        if not startgas:
            startgas = quantity_decoder(self.call('eth_gasLimit')) - 1

        # create transaction
        tx = Transaction(nonce, gasprice, startgas, to=to, value=value, data=data)
        if self.privkey:
            tx.sign(self.privkey)
        tx_dict = tx.to_dict()
        tx_dict.pop('hash')
        for k, v in dict(gasprice='gasPrice', startgas='gas').items():
            tx_dict[v] = tx_dict.pop(k)
        tx_dict['sender'] = sender
        res = self.eth_sendTransaction(**tx_dict)
        assert len(res) in (20, 32)
        return res.encode('hex')

    def new_abi_contract(self, _abi, address):
        sender = self.sender or privtoaddr(self.privkey)
        return ABIContract(sender, _abi, address, self.eth_call, self.send_transaction)


class ABIContract(object):
    """
    proxy for a contract
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


if __name__ == '__main__':
    pass
