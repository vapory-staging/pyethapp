# -*- coding: utf8 -*-
import time
from collections import deque

import eth_protocol
import gevent
import gevent.lock
import rlp
import statistics
from devp2p.protocol import BaseProtocol
from devp2p.service import WiredService
from ethereum.blocks import Block, VerificationFailed
from ethereum.chain import Chain
from ethereum.config import Env
from ethereum.exceptions import InvalidTransaction, InvalidNonce, InsufficientBalance, InsufficientStartGas
from ethereum import config as ethereum_config
from ethereum import processblock
from ethereum.state_transition import validate_transaction
from ethereum.transaction_queue import TransactionQueue
from ethereum.refcount_db import RefcountDB
from ethereum.slogging import get_logger
from ethereum.blocks import get_block_header
from ethereum.transactions import Transaction
from ethereum.utils import sha3
from gevent.queue import Queue
from rlp.utils import encode_hex
from synchronizer import Synchronizer

from pyethapp import sentry
from pyethapp.dao import is_dao_challenge, build_dao_header

log = get_logger('eth.chainservice')

class DuplicatesFilter(object):

    def __init__(self, max_items=128):
        self.max_items = max_items
        self.filter = list()

    def update(self, data):
        "returns True if unknown"
        if data not in self.filter:
            self.filter.append(data)
            if len(self.filter) > self.max_items:
                self.filter.pop(0)
            return True
        else:
            self.filter.append(self.filter.pop(0))
            return False

    def __contains__(self, v):
        return v in self.filter


def update_watcher(chainservice):
    timeout = 180
    d = dict(head=chainservice.chain.head)

    def up(b):
        log.debug('watcher head updated')
        d['head'] = b
    chainservice.on_new_head_cbs.append(lambda b: up(b))

    while True:
        last = d['head']
        gevent.sleep(timeout)
        assert last != d['head'], 'no updates for %d secs' % timeout


class ChainService(WiredService):

    """
    Manages the chain and requests to it.
    """
    # required by BaseService
    name = 'chain'
    default_config = dict(
        eth=dict(network_id=0, genesis='', pruning=-1),
        block=ethereum_config.default_config
    )

    # required by WiredService
    wire_protocol = eth_protocol.ETHProtocol  # create for each peer

    # initialized after configure:
    chain = None
    genesis = None
    synchronizer = None
    config = None
    block_queue_size = 1024
    transaction_queue_size = 1024
    processed_gas = 0
    processed_elapsed = 0

    def __init__(self, app):
        self.config = app.config
        sce = self.config['eth']
        if int(sce['pruning']) >= 0:
            self.db = RefcountDB(app.services.db)
            if "I am not pruning" in self.db.db:
                raise RuntimeError(
                    "The database in '{}' was initialized as non-pruning. "
                    "Can not enable pruning now.".format(self.config['data_dir']))
            self.db.ttl = int(sce['pruning'])
            self.db.db.put("I am pruning", "1")
        else:
            self.db = app.services.db
            if "I am pruning" in self.db:
                raise RuntimeError(
                    "The database in '{}' was initialized as pruning. "
                    "Can not disable pruning now".format(self.config['data_dir']))
            self.db.put("I am not pruning", "1")

        if 'network_id' in self.db:
            db_network_id = self.db.get('network_id')
            if db_network_id != str(sce['network_id']):
                raise RuntimeError(
                    "The database in '{}' was initialized with network id {} and can not be used "
                    "when connecting to network id {}. Please choose a different data directory.".format(
                        self.config['data_dir'], db_network_id, sce['network_id']
                    )
                )

        else:
            self.db.put('network_id', str(sce['network_id']))
            self.db.commit()

        assert self.db is not None

        super(ChainService, self).__init__(app)
        log.info('initializing chain')
        coinbase = app.services.accounts.coinbase
        env = Env(self.db, sce['block'])
        self.chain = Chain(env=env, genesis=sce['genesis_data'], coinbase=coinbase)

        log.info('chain at', number=self.chain.head.number)
        if 'genesis_hash' in sce:
            assert sce['genesis_hash'] == self.chain.genesis.hex_hash, \
                "Genesis hash mismatch.\n  Expected: %s\n  Got: %s" % (
                    sce['genesis_hash'], self.chain.genesis.hex_hash)

        self.synchronizer = Synchronizer(self, force_sync=None)

        self.block_queue = Queue(maxsize=self.block_queue_size)
        #self.transaction_queue = Queue(maxsize=self.transaction_queue_size)
        self.transaction_queue = TransactionQueue()
        self.add_blocks_lock = False
        self.add_transaction_lock = gevent.lock.Semaphore()
        self.broadcast_filter = DuplicatesFilter()
        self.on_new_head_cbs = []
        self.on_new_head_candidate_cbs = []
        self.newblock_processing_times = deque(maxlen=1000)

    @property
    def is_syncing(self):
        return self.synchronizer.synctask is not None

    @property
    def is_mining(self):
        if 'pow' in self.app.services:
            return self.app.services.pow.active
        return False

    # TODO: still need?
    def _on_new_head(self, block):
        log.debug('new head cbs', num=len(self.on_new_head_cbs))
        for cb in self.on_new_head_cbs:
            cb(block)
        self._on_new_head_candidate()  # we implicitly have a new head_candidate

    # TODO: still need?
    def _on_new_head_candidate(self):
        # DEBUG('new head candidate cbs', len(self.on_new_head_candidate_cbs))
        for cb in self.on_new_head_candidate_cbs:
            cb(self.chain.head_candidate)

    def add_transaction(self, tx, origin=None, force_broadcast=False):
        if self.is_syncing:
            if force_broadcast:
                assert origin is None  # only allowed for local txs
                log.debug('force broadcasting unvalidated tx')
                self.broadcast_transaction(tx, origin=origin)
            return  # we can not evaluate the tx based on outdated state
        log.debug('add_transaction', locked=(not self.add_transaction_lock.locked()), tx=tx)
        assert isinstance(tx, Transaction)
        assert origin is None or isinstance(origin, BaseProtocol)

        if tx.hash in self.broadcast_filter:
            log.debug('discarding known tx')  # discard early
            return

        # validate transaction
        try:
            # Transaction validation for broadcasting. Transaction is validated
            # against the (same) head state each time. Conflicting transaction
            # may pass the check.
            validate_transaction(self.chain.state, tx)
            log.debug('valid tx, broadcasting')
            self.broadcast_transaction(tx, origin=origin)  # asap
        except InvalidTransaction as e:
            log.debug('invalid tx', error=e)
            return

        if origin is not None:  # not locally added via jsonrpc
            if not self.is_mining or self.is_syncing:
                log.debug('discarding tx', syncing=self.is_syncing, mining=self.is_mining)
                return

        self.add_transaction_lock.acquire()
        self.transaction_queue.add_transaction(tx)
        self.add_transaction_lock.release()
        return len(self.transaction_queue)

    def add_block(self, t_block, proto):
        "adds a block to the block_queue and spawns _add_block if not running"
        self.block_queue.put((t_block, proto))  # blocks if full
        if not self.add_blocks_lock:
            self.add_blocks_lock = True  # need to lock here (ctx switch is later)
            gevent.spawn(self._add_blocks)

    def add_mined_block(self, block):
        log.debug('adding mined block', block=block)
        assert isinstance(block, Block)
        assert block.header.check_pow()
        if self.chain.add_block(block):
            log.debug('added', block=block, ts=time.time())
            assert block == self.chain.head
            self.broadcast_newblock(block, chain_difficulty=block.chain_difficulty())

    def knows_block(self, block_hash):
        "if block is in chain or in queue"
        if block_hash in self.chain:
            return True
        # check if queued or processed
        for i in range(len(self.block_queue.queue)):
            if block_hash == self.block_queue.queue[i][0].header.hash:
                return True
        return False

    def _add_blocks(self):
        log.debug('add_blocks', qsize=self.block_queue.qsize(),
                  add_tx_lock=self.add_transaction_lock.locked())
        assert self.add_blocks_lock is True
        self.add_transaction_lock.acquire()
        try:
            while not self.block_queue.empty():
                # sleep at the beginning because continue keywords will skip bottom
                gevent.sleep(0.001)

                t_block, proto = self.block_queue.peek()  # peek: knows_block while processing
                if t_block.header.hash in self.chain:
                    log.warn('known block', block=t_block)
                    self.block_queue.get()
                    continue
                if t_block.header.prevhash not in self.chain:
                    log.warn('missing parent', block=t_block, head=self.chain.head)
                    self.block_queue.get()
                    continue
                # FIXME, this is also done in validation and in synchronizer for new_blocks
                if not t_block.header.check_pow():
                    log.warn('invalid pow', block=t_block, FIXME='ban node')
                    sentry.warn_invalid(t_block, 'InvalidBlockNonce')
                    self.block_queue.get()
                    continue
                try:  # deserialize
                    st = time.time()
                    block = t_block.to_block(env=self.chain.env)
                    elapsed = time.time() - st
                    log.debug('deserialized', elapsed='%.4fs' % elapsed, ts=time.time(),
                              gas_used=block.gas_used, gpsec=self.gpsec(block.gas_used, elapsed))
                except InvalidTransaction as e:
                    log.warn('invalid transaction', block=t_block, error=e, FIXME='ban node')
                    errtype = \
                        'InvalidNonce' if isinstance(e, InvalidNonce) else \
                        'NotEnoughCash' if isinstance(e, InsufficientBalance) else \
                        'OutOfGasBase' if isinstance(e, InsufficientStartGas) else \
                        'other_transaction_error'
                    sentry.warn_invalid(t_block, errtype)
                    self.block_queue.get()
                    continue
                except VerificationFailed as e:
                    log.warn('verification failed', error=e, FIXME='ban node')
                    sentry.warn_invalid(t_block, 'other_block_error')
                    self.block_queue.get()
                    continue

                # All checks passed
                log.debug('adding', block=block, ts=time.time())
                if self.chain.add_block(block, forward_pending_transactions=self.is_mining):
                    now = time.time()
                    log.info('added', block=block, txs=block.transaction_count,
                             gas_used=block.gas_used)
                    if t_block.newblock_timestamp:
                        total = now - t_block.newblock_timestamp
                        self.newblock_processing_times.append(total)
                        avg = statistics.mean(self.newblock_processing_times)
                        med = statistics.median(self.newblock_processing_times)
                        max_ = max(self.newblock_processing_times)
                        min_ = min(self.newblock_processing_times)
                        log.info('processing time', last=total, avg=avg, max=max_, min=min_,
                                 median=med)
                else:
                    log.warn('could not add', block=block)

                self.block_queue.get()  # remove block from queue (we peeked only)
        finally:
            self.add_blocks_lock = False
            self.add_transaction_lock.release()

    def gpsec(self, gas_spent=0, elapsed=0):
        if gas_spent:
            self.processed_gas += gas_spent
            self.processed_elapsed += elapsed
        return int(self.processed_gas / (0.001 + self.processed_elapsed))

    def broadcast_newblock(self, block, chain_difficulty=None, origin=None):
        if not chain_difficulty:
            assert block.hash in self.chain
            chain_difficulty = block.chain_difficulty()
        assert isinstance(block, (eth_protocol.TransientBlock, Block))
        if self.broadcast_filter.update(block.header.hash):
            log.debug('broadcasting newblock', origin=origin)
            bcast = self.app.services.peermanager.broadcast
            bcast(eth_protocol.ETHProtocol, 'newblock', args=(block, chain_difficulty),
                  exclude_peers=[origin.peer] if origin else [])
        else:
            log.debug('already broadcasted block')

    def broadcast_transaction(self, tx, origin=None):
        assert isinstance(tx, Transaction)
        if self.broadcast_filter.update(tx.hash):
            log.debug('broadcasting tx', origin=origin)
            bcast = self.app.services.peermanager.broadcast
            bcast(eth_protocol.ETHProtocol, 'transactions', args=(tx,),
                  exclude_peers=[origin.peer] if origin else [])
        else:
            log.debug('already broadcasted tx')

    # wire protocol receivers ###########

    def on_wire_protocol_start(self, proto):
        log.debug('----------------------------------')
        log.debug('on_wire_protocol_start', proto=proto)
        assert isinstance(proto, self.wire_protocol)
        # register callbacks
        proto.receive_status_callbacks.append(self.on_receive_status)
        proto.receive_newblockhashes_callbacks.append(self.on_newblockhashes)
        proto.receive_transactions_callbacks.append(self.on_receive_transactions)
        proto.receive_getblockheaders_callbacks.append(self.on_receive_getblockheaders)
        proto.receive_blockheaders_callbacks.append(self.on_receive_blockheaders)
        proto.receive_getblockbodies_callbacks.append(self.on_receive_getblockbodies)
        proto.receive_blockbodies_callbacks.append(self.on_receive_blockbodies)
        proto.receive_newblock_callbacks.append(self.on_receive_newblock)

        # send status
        head = self.chain.head
        proto.send_status(chain_difficulty=head.chain_difficulty(), chain_head_hash=head.hash,
                          genesis_hash=self.chain.genesis.hash)

    def on_wire_protocol_stop(self, proto):
        assert isinstance(proto, self.wire_protocol)
        log.debug('----------------------------------')
        log.debug('on_wire_protocol_stop', proto=proto)

    def on_receive_status(self, proto, eth_version, network_id, chain_difficulty, chain_head_hash,
                          genesis_hash):
        log.debug('----------------------------------')
        log.debug('status received', proto=proto, eth_version=eth_version)
        assert eth_version == proto.version, (eth_version, proto.version)
        if network_id != self.config['eth'].get('network_id', proto.network_id):
            log.warn("invalid network id", remote_network_id=network_id,
                     expected_network_id=self.config['eth'].get('network_id', proto.network_id))
            raise eth_protocol.ETHProtocolError('wrong network_id')

        # check genesis
        if genesis_hash != self.chain.genesis.hash:
            log.warn("invalid genesis hash", remote_id=proto, genesis=genesis_hash.encode('hex'))
            raise eth_protocol.ETHProtocolError('wrong genesis block')

        # request chain
        self.synchronizer.receive_status(proto, chain_head_hash, chain_difficulty)

        # send transactions
        transactions = self.chain.get_transactions()
        if transactions:
            log.debug("sending transactions", remote_id=proto)
            proto.send_transactions(*transactions)

    # transactions

    def on_receive_transactions(self, proto, transactions):
        "receives rlp.decoded serialized"
        log.debug('----------------------------------')
        log.debug('remote_transactions_received', count=len(transactions), remote_id=proto)
        for tx in transactions:
            self.add_transaction(tx, origin=proto)

    # blockhashes ###########

    def on_newblockhashes(self, proto, newblockhashes):
        """
        msg sent out if not the full block is propagated
        chances are high, that we get the newblock, though.
        """
        log.debug('----------------------------------')
        log.debug("recv newblockhashes", num=len(newblockhashes), remote_id=proto)
        assert len(newblockhashes) <= 256
        self.synchronizer.receive_newblockhashes(proto, newblockhashes)

    def on_receive_getblockheaders(self, proto, hash_or_number, block, amount, skip, reverse):
        hash_mode = 1 if hash_or_number[0] else 0
        block_id = encode_hex(hash_or_number[0]) if hash_mode else hash_or_number[1]
        log.debug('----------------------------------')
        log.debug("handle_getblockheaders", amount=amount, block=block_id)

        headers = []
        max_hashes = min(amount, self.wire_protocol.max_getblockheaders_count)

        if hash_mode:
            origin_hash = hash_or_number[0]
        else:
            if is_dao_challenge(self.config['eth']['block'], hash_or_number[1], amount, skip):
                log.debug("sending: answer DAO challenge")
                headers.append(build_dao_header(self.config['eth']['block']))
                proto.send_blockheaders(*headers)
                return
            try:
                origin_hash = self.chain.index.get_block_by_number(hash_or_number[1])
            except KeyError:
                origin_hash = b''
        if not origin_hash or origin_hash not in self.chain:
            log.debug("unknown block")
            proto.send_blockheaders(*[])
            return

        unknown = False
        while not unknown and (headers) < max_hashes:
            if not origin_hash:
                break
            try:
                origin = get_block_header(self.chain.db, origin_hash)
            except KeyError:
                break
            assert origin
            headers.append(origin)

            if hash_mode:  # hash traversal
                if reverse:
                    for i in xrange(skip+1):
                        try:
                            header = get_block_header(self.chain.db, origin_hash)
                            origin_hash = header.prevhash
                        except KeyError:
                            unknown = True
                            break
                else:
                    origin_hash = self.chain.index.get_block_by_number(origin.number + skip + 1)
                    try:
                        header = get_block_header(self.chain.db, origin_hash)
                        if self.chain.get_blockhashes_from_hash(header.hash, skip+1)[skip] == origin_hash:
                            origin_hash = header.hash
                        else:
                            unknown = True
                    except KeyError:
                        unknown = True
            else:  # number traversal
                if reverse:
                    if origin.number >= (skip+1):
                        number = origin.number - (skip + 1)
                        origin_hash = self.chain.index.get_block_by_number(number)
                    else:
                        unknown = True
                else:
                    number = origin.number + skip + 1
                    try:
                        origin_hash = self.chain.index.get_block_by_number(number)
                    except KeyError:
                        unknown = True

        log.debug("sending: found blockheaders", count=len(headers))
        proto.send_blockheaders(*headers)

    def on_receive_blockheaders(self, proto, blockheaders):
        log.debug('----------------------------------')
        if blockheaders:
            log.debug("on_receive_blockheaders", count=len(blockheaders), remote_id=proto,
                      first=encode_hex(blockheaders[0].hash), last=encode_hex(blockheaders[-1].hash))
        else:
            log.debug("recv 0 remote block headers, signifying genesis block")
        self.synchronizer.receive_blockheaders(proto, blockheaders)

    # blocks ################

    def on_receive_getblockbodies(self, proto, blockhashes):
        log.debug('----------------------------------')
        log.debug("on_receive_getblockbodies", count=len(blockhashes))
        found = []
        for bh in blockhashes[:self.wire_protocol.max_getblocks_count]:
            try:
                found.append(self.chain.db.get(bh))
            except KeyError:
                log.debug("unknown block requested", block_hash=encode_hex(bh))
        if found:
            log.debug("found", count=len(found))
            proto.send_blockbodies(*found)

    def on_receive_blockbodies(self, proto, bodies):
        log.debug('----------------------------------')
        log.debug("recv block bodies", count=len(bodies), remote_id=proto)
        if bodies:
            self.synchronizer.receive_blockbodies(proto, bodies)

    def on_receive_newblock(self, proto, block, chain_difficulty):
        log.debug('----------------------------------')
        log.debug("recv newblock", block=block, remote_id=proto)
        self.synchronizer.receive_newblock(proto, block, chain_difficulty)
