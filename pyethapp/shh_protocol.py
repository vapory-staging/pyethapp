from devp2p.protocol import BaseProtocol, SubProtocolError
import rlp
import gevent
import time
from ethereum import slogging
log = slogging.get_logger('protocol.shh')


class WhisperProtocolError(SubProtocolError):
    pass


class WhisperProtocol(BaseProtocol):

    """
    DEV Ethereum Whisper Protocol
    https://github.com/ethereum/wiki/wiki/Whisper-Wire-Protocol

    """
    protocol_id = 2
    network_id = 0
    max_cmd_id = 2  # FIXME
    name = 'shh'
    version = 2

    def __init__(self, peer, service):
        # required by P2PProtocol
        self.config = peer.config
        BaseProtocol.__init__(self, peer, service)

    class status(BaseProtocol.command):

        """
        protocolVersion: The version of the Whisper protocol this peer implements.
        """
        cmd_id = 0
        sent = False

        structure = [('shh_version', rlp.sedes.big_endian_int)]

        def create(self, proto):
            self.sent = True
            return [proto.version]

    class messages(BaseProtocol.command):

        """
        Messages
        [+0x01: P,
            [expiry1: P, ttl1: P, [topic1x1: B_4, topic1x2: B_4, ...], data1: B, nonce1: P],
            [expiry2: P, ...],
            ...]

        Specify one or more messages. Nodes should not resend the same message to a peer in the
        same session, nor send a message back to a peer from which it received.
        This packet may be empty.
        The packet must be sent at least once per second,
        and only after receiving a Messages message from the peer.
        """
        cmd_id = 1
        structure = rlp.sedes.CountableList(rlp.sedes.binary)



