from gevent.event import AsyncResult
import gevent
import time
from eth_protocol import TransientBlockBody, TransientBlock
from ethereum.blocks import BlockHeader
from ethereum.slogging import get_logger
import ethereum.utils as utils
import traceback

log = get_logger('eth.sync')
log_st = get_logger('eth.sync.task')


class SyncTask(object):

    """
    synchronizes a the chain starting from a given blockhash
    blockchain hash is fetched from a single peer (which led to the unknown blockhash)
    blocks are fetched from the best peers

    with missing block:
        fetch headers
            until known block
    for headers
        fetch block bodies
            for each block body
                construct block
                chainservice.add_blocks() # blocks if queue is full
    """
    initial_blockheaders_per_request = 32
    max_blockheaders_per_request = 192
    max_blocks_per_request = 128
    blocks_request_timeout = 32.
    blockheaders_request_timeout = 32.

    def __init__(self, synchronizer, proto, blockhash, chain_difficulty=0, originator_only=False):
        self.synchronizer = synchronizer
        self.chain = synchronizer.chain
        self.chainservice = synchronizer.chainservice
        self.originating_proto = proto
        self.originator_only = originator_only
        self.blockhash = blockhash
        self.chain_difficulty = chain_difficulty
        self.requests = dict()  # proto: Event
        self.start_block_number = self.chain.head.number
        self.end_block_number = self.start_block_number + 1  # minimum synctask
        gevent.spawn(self.run)

    def run(self):
        log_st.info('spawning new synctask')
        try:
            self.fetch_hashchain()
        except Exception:
            print(traceback.format_exc())
            self.exit(success=False)

    def exit(self, success=False):
        if not success:
            log_st.warn('syncing failed')
        else:
            log_st.debug('successfully synced')
        self.synchronizer.synctask_exited(success)

    @property
    def protocols(self):
        if self.originator_only:
            return [self.originating_proto]
        return self.synchronizer.protocols

    def fetch_hashchain(self):
        log_st.debug('fetching hashchain')
        blockheaders_chain = [] # height falling order
        blockhash = self.blockhash
        assert blockhash not in self.chain

        # get block hashes until we found a known one
        max_blockheaders_per_request = self.initial_blockheaders_per_request
        while blockhash not in self.chain:
            # proto with highest_difficulty should be the proto we got the newblock from
            blockheaders_batch = []

            # try with protos
            protocols = self.protocols
            if not protocols:
                log_st.warn('no protocols available')
                return self.exit(success=False)

            for proto in protocols:
                log.debug('syncing with', proto=proto)
                if proto.is_stopped:
                    continue

                # request
                assert proto not in self.requests
                deferred = AsyncResult()
                self.requests[proto] = deferred
                proto.send_getblockheaders(blockhash, max_blockheaders_per_request)
                try:
                    blockheaders_batch = deferred.get(block=True,
                                                     timeout=self.blockheaders_request_timeout)
                except gevent.Timeout:
                    log_st.warn('syncing hashchain timed out')
                    continue
                finally:
                    # is also executed 'on the way out' when any other clause of the try statement
                    # is left via a break, continue or return statement.
                    del self.requests[proto]

                if not blockheaders_batch:
                    log_st.warn('empty getblockheaders result')
                    continue
                if not all(isinstance(bh, BlockHeader) for bh in blockheaders_batch):
                    log_st.warn('got wrong data type', expected='BlockHeader',
                                received=type(blockheaders_batch[0]))
                    continue
                break

            if not blockheaders_batch:
                log_st.warn('syncing failed with all peers', num_protos=len(protocols))
                return self.exit(success=False)

            for header in blockheaders_batch:  # youngest to oldest
                blockhash = header.hash
                if blockhash not in self.chain:
                    blockheaders_chain.append(header)
                else:
                    log_st.debug('found known block header', blockhash=utils.encode_hex(blockhash),
                                 is_genesis=bool(blockhash == self.chain.genesis.hash))
                    break
            else:  # if all headers in batch added to blockheaders_chain
                blockhash = header.prevhash

            start = "#%d %s" % (blockheaders_chain[0].number, utils.encode_hex(blockheaders_chain[0].hash)[:8])
            end = "#%d %s" % (blockheaders_chain[-1].number, utils.encode_hex(blockheaders_chain[-1].hash)[:8])
            log_st.info('downloaded ' + str(len(blockheaders_chain)) + ' blockheaders', start=start, end=end)
            self.end_block_number = self.chain.head.number + len(blockheaders_chain)
            max_blockheaders_per_request = self.max_blockheaders_per_request

        self.start_block_number = self.chain.get(blockhash).number
        self.end_block_number = self.chain.get(blockhash).number + len(blockheaders_chain)
        log_st.debug('computed missing numbers', start_number=self.start_block_number, end_number=self.end_block_number)
        self.fetch_blocks(blockheaders_chain)

    def fetch_blocks(self, blockheaders_chain):
        # fetch blocks (no parallelism here)
        log_st.debug('fetching blocks', num=len(blockheaders_chain))
        assert blockheaders_chain
        blockheaders_chain.reverse()  # height rising order
        num_blocks = len(blockheaders_chain)
        num_fetched = 0

        while blockheaders_chain:
            blockhashes_batch = [h.hash for h in blockheaders_chain[:self.max_blocks_per_request]]
            t_blocks = []
            bodies = []

            # try with protos
            protocols = self.protocols
            if not protocols:
                log_st.warn('no protocols available')
                return self.exit(success=False)

            for proto in protocols:
                if proto.is_stopped:
                    continue
                assert proto not in self.requests
                # request
                log_st.debug('requesting blocks', num=len(blockhashes_batch), missing=len(blockheaders_chain)-len(blockhashes_batch))
                deferred = AsyncResult()
                self.requests[proto] = deferred
                proto.send_getblockbodies(*blockhashes_batch)
                try:
                    bodies = deferred.get(block=True, timeout=self.blocks_request_timeout)
                except gevent.Timeout:
                    log_st.warn('getblockbodies timed out, trying next proto')
                    continue
                finally:
                    del self.requests[proto]
                if not bodies:
                    log_st.warn('empty getblockbodies reply, trying next proto')
                    continue
                elif not isinstance(bodies[0], TransientBlockBody):
                    log_st.warn('received unexpected data', data=repr(t_blocks))
                    bodies = []
                    continue

            # add received t_blocks
            num_fetched += len(bodies)
            log_st.debug('received block bodies', num=len(bodies), num_fetched=num_fetched,
                         total=num_blocks, missing=num_blocks - num_fetched)

            if not bodies:
                log_st.warn('failed to fetch block bodies', missing=len(blockheaders_chain))
                return self.exit(success=False)

            ts = time.time()
            log_st.debug('adding blocks', qsize=self.chainservice.block_queue.qsize())
            for body in bodies:
                try:
                    h = blockheaders_chain.pop(0)
                    t_block = TransientBlock(h, body.transactions, body.uncles)
                    self.chainservice.add_block(t_block, proto)  # this blocks if the queue is full
                except IndexError as e:
                    log_st.error('headers and bodies mismatch', error=e)
                    self.exit(success=False)
            log_st.debug('adding blocks done', took=time.time() - ts)

        # done
        last_block = t_block
        assert not len(blockheaders_chain)
        assert last_block.header.hash == self.blockhash
        log_st.debug('syncing finished')
        # at this point blocks are not in the chain yet, but in the add_block queue
        if self.chain_difficulty >= self.chain.head.chain_difficulty():
            self.chainservice.broadcast_newblock(last_block, self.chain_difficulty, origin=proto)

        self.exit(success=True)

    def receive_blockbodies(self, proto, bodies):
        log.debug('block bodies received', proto=proto, num=len(bodies))
        if proto not in self.requests:
            log.debug('unexpected blocks')
            return
        self.requests[proto].set(bodies)

    def receive_blockheaders(self, proto, blockheaders):
        log.debug('blockheaders received', proto=proto, num=len(blockheaders))
        if proto not in self.requests:
            log.debug('unexpected blockheaders')
            return
        self.requests[proto].set(blockheaders)


class Synchronizer(object):

    """
    handles the synchronization of blocks

    there is only one synctask active at a time
    in order to deal with the worst case of initially syncing the wrong chain,
        a checkpoint blockhash can be specified and synced via force_sync

    received blocks are given to chainservice.add_block
    which has a fixed size queue, the synchronization blocks if the queue is full

    on_status:
        if peer.head.chain_difficulty > chain.head.chain_difficulty
            fetch peer.head and handle as newblock
    on_newblock:
        if block.parent:
            add
        else:
            sync
    on_blocks/on_blockhashes:
        if synctask:
            handle to requester
        elif unknown and has parent:
            add to chain
        else:
            drop
    """

    MAX_NEWBLOCK_AGE = 5  # maximum age (in blocks) of blocks received as newblock

    def __init__(self, chainservice, force_sync=None):
        """
        @param: force_sync None or tuple(blockhash, chain_difficulty)
                helper for long initial syncs to get on the right chain
                used with first status_received
        """
        self.chainservice = chainservice
        self.force_sync = force_sync
        self.chain = chainservice.chain
        self._protocols = dict()  # proto: chain_difficulty
        self.synctask = None

    def synctask_exited(self, success=False):
        # note: synctask broadcasts best block
        if success:
            self.force_sync = None
        self.synctask = None

    @property
    def protocols(self):
        "return protocols which are not stopped sorted by highest chain_difficulty"
        # filter and cleanup
        self._protocols = dict((p, cd) for p, cd in self._protocols.items() if not p.is_stopped)
        return sorted(self._protocols.keys(), key=lambda p: self._protocols[p], reverse=True)

    def receive_newblock(self, proto, t_block, chain_difficulty):
        "called if there's a newblock announced on the network"
        log.debug('newblock', proto=proto, block=t_block, chain_difficulty=chain_difficulty,
                  client=proto.peer.remote_client_version)

        if t_block.header.hash in self.chain:
            assert chain_difficulty == self.chain.get(t_block.header.hash).chain_difficulty()

        # memorize proto with difficulty
        self._protocols[proto] = chain_difficulty

        if self.chainservice.knows_block(block_hash=t_block.header.hash):
            log.debug('known block')
            return

        # check pow
        if not t_block.header.check_pow():
            log.warn('check pow failed, should ban!')
            return

        expected_difficulty = self.chain.head.chain_difficulty() + t_block.header.difficulty
        if chain_difficulty >= self.chain.head.chain_difficulty():
            # broadcast duplicates filtering is done in eth_service
            log.debug('sufficient difficulty, broadcasting',
                      client=proto.peer.remote_client_version)
            self.chainservice.broadcast_newblock(t_block, chain_difficulty, origin=proto)
        else:
            # any criteria for which blocks/chains not to add?
            age = self.chain.head.number - t_block.header.number
            log.debug('low difficulty', client=proto.peer.remote_client_version,
                      chain_difficulty=chain_difficulty, expected_difficulty=expected_difficulty,
                      block_age=age)
            if age > self.MAX_NEWBLOCK_AGE:
                log.debug('newblock is too old, not adding', block_age=age,
                          max_age=self.MAX_NEWBLOCK_AGE)
                return

        # unknown and pow check and highest difficulty

        # check if we have parent
        if self.chainservice.knows_block(block_hash=t_block.header.prevhash):
            log.debug('adding block')
            self.chainservice.add_block(t_block, proto)
        elif not self.chainservice.is_syncing:
            log.debug('missing parent')
            if not self.synctask:
                self.synctask = SyncTask(self, proto, t_block.header.hash, chain_difficulty)
            else:
                log.debug('existing task, discarding')

    def receive_status(self, proto, blockhash, chain_difficulty):
        "called if a new peer is connected"
        log.debug('status received', proto=proto, chain_difficulty=chain_difficulty)

        # memorize proto with difficulty
        self._protocols[proto] = chain_difficulty

        if self.chainservice.knows_block(blockhash) or self.synctask:
            log.debug('existing task or known hash, discarding')
            return

        if self.force_sync:
            blockhash, chain_difficulty = self.force_sync
            log.debug('starting forced syctask', blockhash=blockhash.encode('hex'))
            self.synctask = SyncTask(self, proto, blockhash, chain_difficulty)

        elif chain_difficulty > self.chain.head.chain_difficulty():
            log.debug('sufficient difficulty')
            self.synctask = SyncTask(self, proto, blockhash, chain_difficulty)

    def receive_newblockhashes(self, proto, newblockhashes):
        """
        no way to check if this really an interesting block at this point.
        might lead to an amplification attack, need to track this proto and judge usefullness
        """
        log.debug('received newblockhashes', num=len(newblockhashes), proto=proto)
        # log.debug('DISABLED')
        # return
        newblockhashes = [h.hash for h in newblockhashes if not self.chainservice.knows_block(h.hash)]
        if (proto not in self.protocols) or (not newblockhashes) or self.synctask:
            log.debug('discarding', known=bool(not newblockhashes), synctask=bool(self.synctask))
            return
        if len(newblockhashes) != 1:
            log.warn('supporting only one newblockhash', num=len(newblockhashes))
        if not self.chainservice.is_syncing:
            blockhash = newblockhashes[0]
            log.debug('starting synctask for newblockhashes', blockhash=blockhash.encode('hex'))
            self.synctask = SyncTask(self, proto, blockhash, 0, originator_only=True)

    def receive_blockbodies(self, proto, bodies):
        log.debug('blockbodies received', proto=proto, num=len(bodies))
        if self.synctask:
            self.synctask.receive_blockbodies(proto, bodies)
        else:
            log.warn('no synctask, not expecting block bodies')

    def receive_blockheaders(self, proto, blockheaders):
        log.debug('blockheaders received', proto=proto, num=len(blockheaders))
        if self.synctask:
            self.synctask.receive_blockheaders(proto, blockheaders)
        else:
            log.warn('no synctask, not expecting blockheaders')
