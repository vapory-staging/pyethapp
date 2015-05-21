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

z_address = '\x00' * 20


class JSONRPCClient(object):
    protocol = JSONRPCProtocol()

    def __init__(self, port=4000, print_communication=True, privkey=None):
        self.transport = HttpPostClientTransport('http://127.0.0.1:{}'.format(port))
        self.print_communication = print_communication
        self.privkey = privkey

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

    def blocknumber(self):
        return quantity_decoder(self.call('eth_blockNumber'))

    def send_transaction(self, to, value=0, data='', startgas=0):
        assert self.privkey
        sender = privtoaddr(self.privkey)
        # fetch nonce
        nonce = self.nonce(sender)
        if not startgas:
            startgas = quantity_decoder(self.call('eth_gasLimit')) - 1

        # create transaction
        default_gasprice = 10000000000042
        tx = Transaction(nonce, default_gasprice, startgas, to=to, value=value, data=data)
        tx.sign(self.privkey)
        tx_dict = tx.to_dict()
        tx_dict.pop('hash')
        for k, v in dict(gasprice='gasPrice', startgas='gas').items():
            tx_dict[v] = tx_dict.pop(k)
        res = self.eth_sendTransaction(**tx_dict)
        if len(res) == 20:
            print 'contract created @', res.encode('hex')
        else:
            assert len(res) == 32
            print 'tx hash', res.encode('hex')
        return res.encode('hex')


    def send_abi_transaction(self, to, abi, method, value=0, *args):
        pass


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
