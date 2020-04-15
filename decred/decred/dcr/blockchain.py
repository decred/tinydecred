"""
Copyright (c) 2020, the Decred developers
"""

import time

from decred.dcr import addrlib, rpc
from decred.dcr.wire.msgblock import BlockHeader
from decred.util import database, helpers
from decred.util.encode import ByteArray


log = helpers.getLogger("blockchain")


class LocalNode:
    """
    LocalNode is a Blockchain based on an authenticated dcrd websocket
    connection.
    """

    def __init__(self, netParams, dbPath, url, user, pw, certPath=None):
        """
        Args:
            netParams (module): The network parameters.
            dbPath (str or Path): A path to a database file for use by the LocalNode.
            url (str): The URL for the local node, with protocol.
            user (str): The user name for authenticating the connection.
            pw (str): The password for authenticating the connection.
            certPath (str or Path): A filepath to the dcrd TLS certificate.
        """
        self.netParams = netParams
        self.db = database.KeyValueDatabase(dbPath)
        self.mainchainDB = self.db.child(
            "mainchain", datatypes=("INTEGER", "BLOB"), blobber=ByteArray
        )
        self.headerDB = self.db.child(
            "headers", blobber=BlockHeader, keyBlobber=ByteArray
        )
        self.socketURL = helpers.makeWebsocketURL(url, "ws")
        self.rpc = None

        def connect():
            self.close()
            self.rpc = rpc.WebsocketClient(self.socketURL, user, pw, cert=certPath)

        self.connect = connect
        connect()

    def close(self):
        """
        Close the node connection.
        """
        if self.rpc:
            self.rpc.close()

    def connected(self):
        """
        Whether the websocket client appears to be connected.

        Returns:
            bool: True if connected.
        """
        return self.rpc and not self.rpc.closed

    def header(self, blockHash):
        """
        Get the header, from the headerDB if possible, otherwise fetch from RPC.

        Args:
            blockHash (ByteArray): The block header hash.

        Returns:
            BlockHeader: The block header.
        """
        try:
            return self.headerDB[blockHash]
        except database.NoValueError:
            header = self.rpc.getBlockHeader(blockHash, verbose=False)
            self.headerDB[header.cachedHash()] = header
            return header

    def blockHash(self, height):
        """
        Get the block hash for the specified height, from mainchainDB if
        possible, otherwise fetch from RPC.

        Args:
            height (int): The block height.

        Returns:
            ByteArray: The block hash.
        """
        try:
            return self.mainchainDB[height]
        except database.NoValueError:
            return self.rpc.getBlockHash(height)

    def discoverAddresses(self, xPub, idx, gap):
        """
        Find all addresses associated with the extended public key, beginning at
        index and looking up to gap addresses past the last seen address. For
        example, if startIdx = 5, and gap = 5, and no new addresses are found
        before 5 + 5 = 10, then no results will be returned. If, on the other
        hand, a result is found at index 9, addresses will be checked up to
        index 14. If an address is then found at index 13, result will be
        checked  up to 18, and so on.

        Args:
            xPub (ExtendedKey): The extended public key for the external account
                branch.
            idx (int): The child index at which to start the scan.
            gap (int): The maximum number of unseen addresses allowed before
                quitting the scan.

        Returns:
            list(int): The discovered address indices.
        """
        discovered = []
        netParams = self.netParams
        end = idx + gap
        lastSeen = idx

        its = 0
        startTime = time.time()
        while end > idx:
            its += 1
            addrs = [
                addrlib.deriveChildAddress(xPub, i, netParams)
                for i in range(idx, end + 1)
            ]
            founds = self.rpc.existsAddresses(addrs)
            for j, found in enumerate(founds):
                if found:
                    discovered.append(idx + j)
                    lastSeen = idx + j
            idx = end + 1
            end = lastSeen + 1 + gap

        duration = time.time() - startTime
        log.debug(
            f"{its} iterations to discover {len(discovered)}"
            f" addresses. {duration:.3f} seconds"
        )

        return discovered

    def syncAccount(self, addrs, outPoints, startHash):
        """
        Sync an account.

        Args:
            addrs list(str): A list of addresses for the transaction filter.
            outPoints list(msgtx.OutPoint): A list of outpoints for the
                transaction filter.
            startHash (ByteArray): Scans will be started at this block. If
                startHash is not specified, the scan will be started at the root
                block, which is probably not the genesis block. See syncHeaders
                documentation for more info on the root block.

        Return:
            list(RescanBlock): The discovered transactions grouped by block
                hash.
        """
        self.rpc.loadTxFilter(True, addrs, outPoints)
        maxBlocksPerRescan = 2000
        mainchain = self.mainchainDB

        startHeader = self.headerDB[startHash]
        start = startHeader.height
        tipHeight = mainchain.last()[0]
        toScan = tipHeight - start + 1
        log.info(f"synchronizing {toScan} blocks")
        rescanBlocks = []
        while start <= tipHeight:
            blockHashes = [x[1] for x in mainchain[start : start + maxBlocksPerRescan]]
            rescanBlocks.extend(self.rpc.rescan(blockHashes))
            start += maxBlocksPerRescan

        return rescanBlocks

    def syncHeaders(self, root):
        """
        Synchronize headers after specified blockHash. It is assumed that root
        block is a mainchain block, a condition easily met if wallets choose
        their initial root block to be a few blocks before the tip at wallet
        creation.

        Args:
            root (ByteArray): The block hash of the root.

        Returns:
            list(ByteArray): A list of hashes for blocks removed from mainchain.
        """
        synced = 0  # Keep a count of the number of headers synced.
        mainchain = self.mainchainDB

        # Get the root header
        rootHeader = self.header(root)
        startTime = time.time()

        # Get the current db tip. Store the root block if mainchain bucket is
        # empty.
        try:
            tipHeight, tipHash = mainchain.last()

        except database.NoValueError:

            # Seed the root block.
            tipHash = rootHeader.cachedHash()
            tipHeight = rootHeader.height
            mainchain[tipHeight] = tipHash
            log.info(f"stored root block at height {tipHeight}")
            synced = 1

        # Check for missing blocks before the current root.
        currentRootHeight, currentRootHash = mainchain.first()
        if currentRootHeight > rootHeader.height:
            log.info(f"storing a new root block at height {rootHeader.height}")
            mainchain[rootHeader.height] = rootHeader.cachedHash()
            synced += 1 + self.syncHeaderRange(rootHeader.height, currentRootHeight - 1)

        # Prune orphans.
        orphans = []
        while self.rpc.getBlockHash(tipHeight) != tipHash:
            orphans.append(tipHash)
            del mainchain[tipHeight]
            tipHeight -= 1
            tipHash = mainchain[tipHeight]

        # Get the current node tip and synchronize the rest.
        nodeTip = self.rpc.getBestBlock().height
        if nodeTip > tipHeight:
            synced += self.syncHeaderRange(tipHeight, nodeTip)

        secs = int(time.time() - startTime)
        log.info(f"{secs} seconds to sync {synced} block headers")

        height, blockHash = mainchain.last()
        log.info(f"best block {reversed(blockHash).hex()} at height {nodeTip}")

        return synced, orphans

    def syncHeaderRange(self, start, end):
        """
        Retrieve and store mainchain block headers in the range (start:end],
        e.g. start is not included.

        Args:
            start (int): The start height. The block for this height is not
                synced except in the special case of start = 0, which does
                trigger storage of the genesis block.
            end (int): The last block to sync. This block for this height will
                be synced.

        Returns:
            int: The count of headers stored.
        """

        storage = self.headerDB
        mainchain = self.mainchainDB
        # Keep a count of the actual number synced. This can be < start - end.
        synced = 0
        if start == 0:
            # store the genesis block
            genesis = self.header(self.blockHash(0))
            storage[genesis.cachedHash()] = genesis
            mainchain[0] = genesis.cachedHash()
            start = 1
            synced = 1

        startHash = self.blockHash(start)
        stopHash = self.blockHash(end)
        iterationTime = time.time()
        headers = self.rpc.getHeaders([startHash], stopHash)
        while headers:
            synced += len(headers)
            log.info(f"storing headers from height {start+1} to {start+len(headers)}")
            storage.batchInsert((header.cachedHash(), header) for header in headers)
            mainchain.batchInsert(
                (start + i + 1, header.cachedHash()) for i, header in enumerate(headers)
            )
            log.debug(
                f"{(time.time() - iterationTime) * 1e3:.3f} ms"
                f" to fetch and insert {len(headers)} headers"
            )
            startHash = headers[-1].cachedHash()
            if startHash == stopHash:
                break
            iterationTime = time.time()
            start += len(headers)
            headers = self.rpc.getHeaders([startHash], stopHash)

        return synced
