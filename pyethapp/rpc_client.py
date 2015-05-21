"""Provides a simple way of testing JSON RPC commands."""
import json
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.http import HttpPostClientTransport
from pyethapp.jsonrpc import quantity_encoder, quantity_decoder
from pyethapp.jsonrpc import address_encoder, data_encoder, data_decoder, address_decoder
from pyethapp.jsonrpc import default_gasprice, default_startgas
from ethereum.transactions import Transaction
from pyethapp.accounts import mk_privkey, privtoaddr
from ethereum import abi
from ethereum.utils import denoms

z_address = '\x00' * 20


class JSONRPCClient(object):
    protocol = JSONRPCProtocol()

    def __init__(self, port=4000, print_communication=True, privkey=None, sender=None):
        "specify privkey for local signing"
        self.transport = HttpPostClientTransport('http://127.0.0.1:{}'.format(port))
        self.print_communication = print_communication
        self.privkey = privkey
        self._sender = sender

    @property
    def sender(self):
        if self.privkey: 
            return privtoaddr(self.privkey)
        if self._sender is None:
            self._sender = self.coinbase
        return self._sender


    def call(self, method, *args, **kwargs):
        request = self.protocol.create_request(method, args, kwargs)
        reply = self.transport.send_message(request.serialize())
        if self.print_communication:
            print "Request:"
            print json.dumps(json.loads(request.serialize()), indent=2)
            print "Reply:"
            print reply
        return self.protocol.parse_reply(reply).result

    __call__ = call

    def find_block(self, condition):
        """Query all blocks one by one and return the first one for which
        `condition(block)` evaluates to `True`.
        """
        i = 0
        while True:
            block = self.call('eth_getBlockByNumber', quantity_encoder(i), True, print_comm=False)
            if condition(block):
                return block
            i += 1

    def eth_sendTransaction(self, nonce=None, sender='', to='', value=0, data='',
                            gasPrice=default_gasprice, gas=default_startgas,
                            v=None, r=None, s=None):
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


    def nonce(self, address):
        if len(address) == 40:
            address = address.decode('hex')
        return quantity_decoder(
            self.call('eth_getTransactionCount', address_encoder(address), 'pending'))


    @property
    def coinbase(self):
        return address_decoder(self.call('eth_coinbase'))


    def send_transaction(self, sender, to, value=0, data='', startgas=0, gasprice=10*denoms.szabo):
        "can send a locally signed transaction if privkey is given"
        assert self.privkey or sender
        if self.privkey:
            _sender = sender
            sender = privtoaddr(self.privkey)
            assert sender == _sender
        # fetch nonce
        nonce = self.nonce(sender)
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
        res = self.eth_sendTransaction(**tx_dict)
        assert len(res) in (20,32)
        return res.encode('hex')


    def eth_call(self, sender='', to='', value=0, data='', gasPrice=default_gasprice,
                gas=default_startgas):
        "call on pending block"
        encoders = dict(sender=address_encoder, to=data_encoder,
                        value=quantity_encoder, gasPrice=quantity_encoder,
                        gas=quantity_encoder, data=data_encoder)
        data = {k: encoders[k](v) for k, v in locals().items()
                if k not in ('self', 'encoders') and v is not None}
        data['from'] = data.pop('sender')
        res = self.call('eth_call', data)
        return data_decoder(res)

    def new_abi_contract(self, _abi, address):
        return ABIContract(self, _abi, address)

def address20(address):
    if len(address) == '42':
        address = address[2:]
    if len(address) == 40:
        address = address.decode('hex')
    assert len(address) == 20
    return address

class ABIContract():
    """
    proxy for a contract
    """

    def __init__(self, rpc_client, _abi, address):
        self._translator = abi.ContractTranslator(_abi)
        self.abi = _abi
        address = address20(address)

        class abi_method(object):
            
            def __init__(this, f):
                this.f = f

            def transact(this, *args):
                data = self._translator.encode(this.f, args)
                txhash = rpc_client.send_transaction(
                            sender=address20(rpc_client.sender),
                            to=address,
                            value=0,
                            data=data)               
                return txhash

            def call(this, *args):            
                data = self._translator.encode(this.f, args)
                res = rpc_client.eth_call(
                            sender=address20(rpc_client.sender),
                            to=address,
                            value=0,
                            data=data)
                if res:
                    res = self._translator.decode(this.f, res)
                    res = res[0] if len(res) == 1 else res
                return res

            def __call__(this, *args):
                if self._translator.function_data[this.f]['is_constant']:
                    return this.call(*args)
                else:
                    return this.transact(*args)

        for f in self._translator.function_data:
            setattr(self, f, abi_method(f))



def tx_example():
    """
    unsigned txs is signed on the server which needs to know
    the secret key associated with the sending account
    it can be added in the config
    """
    from pyethapp.accounts import mk_privkey, privtoaddr
    secret_seed = 'wow'
    sender = privtoaddr(mk_privkey(secret_seed))
    res = JSONRPCClient().eth_sendTransaction(sender=sender, to=z_address, value=1000)
    if len(res) == 20:
        print 'contract created @', res.encode('hex')
    else:
        assert len(res) == 32
        print 'tx hash', res.encode('hex')


def signed_tx_example(to=z_address, value=100):
    from ethereum.transactions import Transaction
    from pyethapp.accounts import mk_privkey, privtoaddr
    secret_seed = 'wow'
    privkey = mk_privkey(secret_seed)
    sender = privtoaddr(privkey)
    # fetch nonce
    nonce = quantity_decoder(
        JSONRPCClient().call('eth_getTransactionCount', address_encoder(sender), 'pending'))
    # create transaction
    tx = Transaction(nonce, default_gasprice, default_startgas, to=z_address, value=value, data='')
    tx.sign(privkey)
    tx_dict = tx.to_dict()
    tx_dict.pop('hash')
    res = JSONRPCClient().eth_sendTransaction(**tx_dict)
    if len(res) == 20:
        print 'contract created @', res.encode('hex')
    else:
        assert len(res) == 32
        print 'tx hash', res.encode('hex')


def get_balance(account):
    b = quantity_decoder(
        JSONRPCClient().call('eth_getBalance', address_encoder(account), 'pending'))
    return b


if __name__ == '__main__':
    call = JSONRPCClient()
    # signed_tx_example()
    # tx_example()
