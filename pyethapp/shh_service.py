import rlp
from ethereum.slogging import get_logger
from devp2p.service import WiredService
import shh_protocol
from ethereum.utils import DEBUG

log = get_logger('shh.service')


class WhisperService(WiredService):

    # required by BaseService
    name = 'whisper'
    default_config = dict(shh=dict())

    # required by WiredService
    wire_protocol = shh_protocol.WhisperProtocol  # create for each peer

    def __init__(self, app):
        self.config = app.config
        super(WhisperService, self).__init__(app)
        log.info('initializing whisper')

    # wire protocol receivers ###########

    def on_wire_protocol_start(self, proto):
        log.debug('----------------------------------')
        log.debug('on_wire_protocol_start', proto=proto)
        DEBUG('wire protocol started')
        assert isinstance(proto, self.wire_protocol)
        # register callbacks
        proto.receive_status_callbacks.append(self.on_receive_status)
        proto.receive_messages_callbacks.append(self.on_receive_messages)

        print proto.peer.protocols

        # send status
        proto.send_status()

    def on_wire_protocol_stop(self, proto):
        assert isinstance(proto, self.wire_protocol)
        log.debug('----------------------------------')
        log.debug('on_wire_protocol_stop', proto=proto)

    def on_receive_status(self, proto, shh_version):
        log.debug('----------------------------------')
        log.debug('status received', proto=proto, version=shh_version)
        assert shh_version == proto.version, (shh_version, proto.version)
        DEBUG('wire protocol status received')

    def on_receive_messages(self, proto, messages):
        "receives rlp.decoded serialized"
        log.debug('----------------------------------')
        log.debug('remote_messages_received', count=len(messages), remote_id=proto)
        DEBUG('wire protocol messages received')
