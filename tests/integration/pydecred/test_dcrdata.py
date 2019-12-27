"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os
import unittest
from tempfile import TemporaryDirectory
import time

from tinydecred.pydecred import mainnet, testnet, txscript, dcrdata
from tinydecred.pydecred.wire import msgtx
from tinydecred.crypto import crypto


class TestDcrdata(unittest.TestCase):
    def client(self, **k):
        return dcrdata.DcrdataClient("https://alpha.dcrdata.org", **k)

    def test_websocket(self):
        """
        "newblock":       SigNewBlock,
        "mempool":        SigMempoolUpdate,
        "ping":           SigPingAndUserCount,
        "newtxs":         SigNewTxs,
        "address":        SigAddressTx,
        "blockchainSync": SigSyncStatus,
        """

        def emitter(o):
            print("msg: %s" % repr(o))

        client = self.client(emitter=emitter)
        client.subscribeAddresses("Dcur2mcGjmENx4DhNqDctW5wJCVyT3Qeqkx")
        time.sleep(1)
        client.close()

    def test_get_block_header(self):
        with TemporaryDirectory() as tempDir:
            blockchain = dcrdata.DcrdataBlockchain(
                os.path.join(tempDir, "db.db"), mainnet, "https://alpha.dcrdata.org"
            )
            blockchain.connect()
            blockchain.blockHeader(
                "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
            )
            blockchain.close()

    def test_purchase_ticket(self):
        from tinydecred.crypto.secp256k1 import curve as Curve
        from tinydecred.crypto import rando

        with TemporaryDirectory() as tempDir:
            blockchain = dcrdata.DcrdataBlockchain(
                os.path.join(tempDir, "db.db"), testnet, "https://testnet.dcrdata.org"
            )
            blockchain.connect()

            def broadcast(txHex):
                print("test skipping broadcast of transaction: %s" % txHex)
                return True

            blockchain.broadcast = broadcast
            txs = {}

            def getTx(txid):
                return txs[txid]

            blockchain.tx = getTx
            addrs = []
            keys = {}

            def newTxid():
                return crypto.hashH(rando.generateSeed(20)).hex()

            def internal():
                privKey = Curve.generateKey()
                pkHash = crypto.hash160(privKey.pub.serializeCompressed().b)
                addr = crypto.AddressPubKeyHash(testnet.PubKeyHashAddrID, pkHash)
                addrs.append(addr)
                keys[addr.string()] = privKey
                return addr.string()

            def priv(addr):
                return keys[addr]

            class KeySource:
                def priv(self, *a):
                    return priv(*a)

                def internal(self):
                    return internal()

            def utxosource(amt, filter):
                nextVal = 10
                total = 0
                utxos = []

                while total < amt:
                    atoms = int(nextVal * 1e8)
                    privKey = Curve.generateKey()
                    pkHash = crypto.hash160(privKey.pub.serializeCompressed().b)
                    addr = crypto.AddressPubKeyHash(testnet.PubKeyHashAddrID, pkHash)
                    addrs.append(addr)
                    addrString = addr.string()
                    keys[addrString] = privKey
                    pkScript = txscript.makePayToAddrScript(addrString, testnet)
                    txid = newTxid()
                    utxos.append(
                        dcrdata.UTXO(
                            address=addrString,
                            txid=txid,
                            vout=0,
                            ts=int(time.time()),
                            scriptPubKey=pkScript,
                            amount=nextVal,
                            satoshis=atoms,
                        )
                    )
                    tx = msgtx.MsgTx.new()
                    tx.addTxOut(msgtx.TxOut(value=atoms, pkScript=pkScript))
                    txs[txid] = tx
                    total += atoms
                    nextVal *= 2
                return utxos, True

            poolPriv = Curve.generateKey()
            pkHash = crypto.hash160(poolPriv.pub.serializeCompressed().b)
            poolAddr = crypto.AddressPubKeyHash(testnet.PubKeyHashAddrID, pkHash)
            scriptHash = crypto.hash160("some script. doesn't matter".encode())
            scriptAddr = crypto.AddressScriptHash(testnet.ScriptHashAddrID, scriptHash)
            ticketPrice = blockchain.stakeDiff()

            class request:
                minConf = 0
                expiry = 0
                spendLimit = ticketPrice * 2 * 1.1
                poolAddress = poolAddr.string()
                votingAddress = scriptAddr.string()
                ticketFee = 0
                poolFees = 7.5
                count = 2
                txFee = 0

            ticket, spent, newUTXOs = blockchain.purchaseTickets(
                KeySource(), utxosource, request()
            )
