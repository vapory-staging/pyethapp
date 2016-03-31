from pyethapp.rpc_client import JSONRPCClient

def test_find_block():
    JSONRPCClient.call = lambda self, cmd, num, flag: num
    client = JSONRPCClient()
    client.find_block(lambda x: x == '0x5')


def test_default_host():
    default_host = 'http://127.0.0.1'
    client = JSONRPCClient()
    assert client.transport.endpoint == '{}:{}'.format(default_host, client.port)


def test_set_host():
    host = 'http://1.1.1.1'
    default_host = 'http://127.0.0.1'
    client = JSONRPCClient(host)
    assert client.transport.endpoint == '{}:{}'.format(host, client.port)
    assert client.transport.endpoint != '{}:{}'.format(default_host, client.port)
