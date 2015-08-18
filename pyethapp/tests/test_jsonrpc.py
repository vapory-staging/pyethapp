import pytest

solidity_code = "contract test { function multiply(uint a) returns(uint d) {   return a * 7;   } }"
def test_compileSolidity():
    from pyethapp.jsonrpc import Compilers, data_encoder
    import ethereum._solidity
    s = ethereum._solidity.get_solidity()
    if s == None:
        pytest.xfail("solidity not installed, not tested")
    else:
        c = Compilers()
        bc = s.compile(solidity_code)
        abi = s.mk_full_signature(solidity_code)
        r = dict(code=data_encoder(bc),
             info=dict(source=solidity_code,
                       language='Solidity',
                       languageVersion='0',
                       compilerVersion='0',
                       abiDefinition=abi,
                       userDoc=dict(methods=dict()),
                       developerDoc=dict(methods=dict()),
                       )
             )
        assert r == c.compileSolidity(solidity_code)
