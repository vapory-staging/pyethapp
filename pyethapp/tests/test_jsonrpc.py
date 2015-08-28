import pytest

from pyethapp.jsonrpc import Compilers


solidity_code = "contract test { function multiply(uint a) returns(uint d) {   return a * 7;   } }"


@pytest.mark.skipif('solidity' not in Compilers().compilers, reason="solidity compiler not available")
def test_compileSolidity():
    result = Compilers().compileSolidity(solidity_code)
    assert set(result.keys()) == {'test'}
    assert set(result['test'].keys()) == {'info', 'code'}
    assert set(result['test']['info']) == {
        'language', 'languageVersion', 'abiDefinition', 'source',
        'compilerVersion', 'developerDoc', 'userDoc'
    }
