import os
import pytest
from subprocess import Popen

#def test_externally(test_app, tmpdir):


def prepare_rpc_tests(tmpdir):
    rpc_tests = tmpdir.mkdir('testdata')

    assert Popen(['git', 'clone', 'https://github.com/ethereum/rpc-tests'], cwd=str(rpc_tests)).wait() == 0
    tests_dir = rpc_tests.join('rpc-tests')
    assert Popen(['git', 'submodule', 'update', '--init', '--recursive'], cwd=str(tests_dir)).wait() == 0
    assert Popen(['npm', 'install'], cwd=str(tests_dir)).wait() == 0
    return tests_dir


@pytest.fixture()
def test_setup(request, tmpdir):
    """
    start the test_app with `subprocess.Popen`, so we can kill it properly.
    :param request:
    :param tmpdir:
    :return:
    """
    rpc_tests_dir = prepare_rpc_tests(tmpdir)

    test_data = rpc_tests_dir.join('lib/tests/BlockchainTests/bcRPC_API_Test.json')

    test_app = Popen([
        'pyethapp',
        '-d', str(tmpdir),
        '-l:info,eth.chainservice:debug,jsonrpc:debug',
        '-c jsonrpc.listen_port=8081',
        '-c p2p.max_peers=0',
        '-c p2p.min_peers=0',
        'blocktest',
        str(test_data),
        'RPC_API_Test'
    ])
    def fin():
        test_app.terminate()
    request.addfinalizer(fin)

    return (test_app, rpc_tests_dir)

@pytest.mark.skipif(os.getenv('TRAVIS') != None, reason="don't start external test on travis")
def test_eth(test_setup):
    # The results of the external rpc-tests are not evaluated as:
    #  1) the Whisper protocol is not implemented and its tests fail;
    #  2) the eth_accounts method should be skipped;
    #  3) the eth_getFilterLogs fails due to the invalid test data;

    (test_app, rpc_tests_dir) = test_setup
    tests = Popen(['make', 'test.eth'], cwd=str(rpc_tests_dir)).wait()
    assert False, tests.stdout
    #FIXME: parse test results and generate report in a pytest compatible format
