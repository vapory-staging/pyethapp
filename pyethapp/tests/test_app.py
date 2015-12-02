import pytest
from pyethapp import app
from click.testing import CliRunner

genesis_dict = {
    "nonce": "0x00000000000000ff",
    "difficulty": "0xff0000000",
    "mixhash": "0xff00000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0xff00000000000000000000000000000000000000",
    "timestamp": "0xff",
    "parentHash": "0xff00000000000000000000000000000000000000000000000000000000000000",
    "extraData": "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
    "gasLimit": "0xffff",
    "alloc": {
        "ffffffffffffffffffffffffffffffffffffffff": {"balance": "9876543210"},
        "0000000000000000000000000000000000000000": {"balance": "1234567890"}
    }
}


genesis_yaml = """
eth:
  genesis: {}
""".format(genesis_dict)


def test_show_usage():
    runner = CliRunner()
    result = runner.invoke(app.app, [])
    assert "Usage: app " in result.output


@pytest.mark.parametrize('option', ['-C', '--Config', '-c'])
def test_custom_config_file(option):
    runner = CliRunner()
    with runner.isolated_filesystem():

        arg = {
            '-C': 'myconfig.yaml',
            '--Config': 'myconfig.yaml',
            '-c': "eth.genesis={}".format(genesis_dict).replace('\n', '').replace(' ', '')
        }

        if arg[option].endswith('.yaml'):
            with open(arg[option], 'w') as text_file:
                text_file.write(genesis_yaml)

        result = runner.invoke(app.app, [option, arg[option], 'config'])

        for k, v in genesis_dict.items():
            if k != 'alloc':
                assert "{}: '{}'".format(k, v) in result.output, k

        for k, v in genesis_dict['alloc'].items():
            assert k in result.output
            assert v['balance'] in result.output


if __name__ == '__main__':
    test_custom_config_file('-C')
    test_custom_config_file('--Config')
    test_custom_config_file('-c')
