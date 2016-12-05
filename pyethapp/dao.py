from ethereum.blocks import BlockHeader
from ethereum.utils import decode_hex, int256, big_endian_to_int


def is_dao_challenge(config, number, amount, skip):
    return number == config['DAO_FORK_BLKNUM'] and amount == 1 and skip == 0


def build_dao_header(config):
    return BlockHeader(
        prevhash=decode_hex('a218e2c611f21232d857e3c8cecdcdf1f65f25a4477f98f6f47e4063807f2308'),
        uncles_hash=decode_hex('1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347'),
        coinbase=decode_hex('bcdfc35b86bedf72f0cda046a3c16829a2ef41d1'),
        state_root=decode_hex('c5e389416116e3696cce82ec4533cce33efccb24ce245ae9546a4b8f0d5e9a75'),
        tx_list_root=decode_hex('7701df8e07169452554d14aadd7bfa256d4a1d0355c1d174ab373e3e2d0a3743'),
        receipts_root=decode_hex('26cf9d9422e9dd95aedc7914db690b92bab6902f5221d62694a2fa5d065f534b'),
        bloom=int256.deserialize(
            decode_hex('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
        ),
        difficulty=big_endian_to_int(decode_hex('38c3bf2616aa')),
        number=config['DAO_FORK_BLKNUM'],
        gas_limit=big_endian_to_int(decode_hex('47e7c0')),
        gas_used=big_endian_to_int(decode_hex('014820')),
        timestamp=big_endian_to_int(decode_hex('578f7aa8')),
        extra_data=config['DAO_FORK_BLKEXTRA'],
        mixhash=decode_hex('5b5acbf4bf305f948bd7be176047b20623e1417f75597341a059729165b92397'),
        nonce=decode_hex('bede87201de42426')
    )
