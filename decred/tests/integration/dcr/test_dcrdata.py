"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import os
from tempfile import TemporaryDirectory
import time
import unittest

from decred.crypto import crypto, rando
from decred.crypto.secp256k1 import curve as Curve
from decred.dcr import account, dcrdata, txscript
from decred.dcr.nets import mainnet, testnet
from decred.dcr.wire import msgtx
from decred.util import encode


ByteArray = encode.ByteArray


def newHash():
    return ByteArray(rando.generateSeed(32))


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
            try:
                blockchain.connect()
                blockchain.blockHeader(
                    "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
                )
            finally:
                blockchain.close()

    def test_purchase_ticket(self):
        with TemporaryDirectory() as tempDir:
            blockchain = dcrdata.DcrdataBlockchain(
                os.path.join(tempDir, "db.db"), testnet, "https://testnet.dcrdata.org"
            )
            try:
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
                        addr = crypto.AddressPubKeyHash(
                            testnet.PubKeyHashAddrID, pkHash
                        )
                        addrs.append(addr)
                        addrString = addr.string()
                        keys[addrString] = privKey
                        pkScript = txscript.makePayToAddrScript(addrString, testnet)
                        txHash = newHash()
                        txid = reversed(txHash).hex()
                        utxos.append(
                            account.UTXO(
                                address=addrString,
                                txHash=txHash,
                                vout=0,
                                ts=int(time.time()),
                                scriptPubKey=pkScript,
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
                scriptAddr = crypto.AddressScriptHash(
                    testnet.ScriptHashAddrID, scriptHash
                )
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
            finally:
                blockchain.close()

    def test_revoke_ticket(self):
        with TemporaryDirectory() as tempDir:
            blockchain = dcrdata.DcrdataBlockchain(
                os.path.join(tempDir, "db.db"), testnet, "https://testnet.dcrdata.org"
            )
            blockchain.connect()

            def broadcast(txHex):
                print("test skipping broadcast of transaction: %s" % txHex)
                return True

            blockchain.broadcast = broadcast

            class test:
                def __init__(
                    self, ticket="", privKey="", redeemScript="", revocation="",
                ):
                    self.ticket = ticket
                    self.privKey = privKey
                    self.redeemScript = redeemScript
                    self.revocation = revocation

            tests = [
                test(
                    "010000000210fd1f5623e2469d9bb390ad21b12f6710f5d6be0e130df074cfd8614d0c4e050400000000ffffffff10fd1f5623e2469d9bb390ad21b12f6710f5d6be0e130df074cfd8614d0c4e050500000000ffffffff05508f4a7401000000000018baa91438a8a93737e62e806f49d1465518a02f110d57fe8700000000000000000000206a1e1aee120db13f4e4f785aec3da97b48963de58ebd37570200000000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000000000000000206a1eabc7372997a530b43e8e17a4850602b28e0768dd454d4874010000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac000000000000000002375702000000000000000000000000006a47304402202b5f4a97abf78d95875de75b244f9b4c7f60bb40b01a91881331022a03a3bf32022047f951e0414e4f28518b5254974abeb93f77727bee7c6fbd5010f8bf375dd10f012102ec908402cb3ab128a9a68978fbb3b33f1c97d715afb8f76dbbe300619878f095454d48740100000000000000000000006a47304402200435095049ac7b3f3c47a43d92afc22db032b929357f2f216eb24e91cd0d2d2802203ca93654cc1f193f11ce0c7e74f9959edd984c15d54f99b0d227b1cdd99a4a3e012102ec908402cb3ab128a9a68978fbb3b33f1c97d715afb8f76dbbe300619878f095",
                    "d407f81cb789e65579590d5e50027431f1fdea21c2ebef12944b7842e71eaf",
                    "51210289a43bf822daf338bb07555476a967cc46545a58c513a0badc99861c81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131f6f6a5c88ad9dfedd53f9b52ae",
                    "0100000001113d36ae0156c1f5a3071de1f7f10e9e4521a77266b1927f832babb9fe3d5cd90000000001ffffffff022c4d02000000000000001abc76a9141aee120db13f4e4f785aec3da97b48963de58ebd88ac193848740100000000001abc76a914abc7372997a530b43e8e17a4850602b28e0768dd88ac000000000000000001508f4a740100000000000000000000009148304502210099b8e13022e13d19229fff3a2b08ebf54f5cd4ea79c85618d04a57a735283e9102203e0fd5a66a168edff1bbcaeaa9d5b2d5e224cbd5d90a6c0099c73810d7493924014751210289a43bf822daf338bb07555476a967cc46545a58c513a0badc99861c81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131f6f6a5c88ad9dfedd53f9b52ae",
                ),
                test(
                    "010000000228a301cae233e252143e6fff3ccd348e156bbcc8ea158cfb4a1fe19f78cad1e80a00000000ffffffff28a301cae233e252143e6fff3ccd348e156bbcc8ea158cfb4a1fe19f78cad1e80b00000000ffffffff05d00fb2fb00000000000018baa91438a8a93737e62e806f49d1465518a02f110d57fe8700000000000000000000206a1e1aee120db13f4e4f785aec3da97b48963de58ebdcf550200000000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac00000000000000000000206a1e949293b5f8acd5a0a871ce417cd5354d9715a2912dcfaffb000000000058000000000000000000001abd76a914000000000000000000000000000000000000000088ac000000000000000002cf5502000000000000000000000000006b483045022100a4072a6a09058cf1b2713b75e636bcdf418c9897aa18cd584cfcf0229bf6b7d102200cb94cfef85a31943ab1e0daba90578c3b465be26e4a94a19e1da5ec70586193012103ac3936e6c8d0fd9cefde6cc9552289c943a1eb4abe1601de8f8e46b8f7ed508d2dcfaffb0000000000000000000000006a47304402202fc0578332b69746109066cc7d7cb9b86f0a693639bbe4dc84c83f26ef0e3bad022010ad57133bcc77bb36600488679f5da6ab6740b4d743470bcd60f2ecda70aa7f012103ac3936e6c8d0fd9cefde6cc9552289c943a1eb4abe1601de8f8e46b8f7ed508d",
                    "d407f81cb789e65579590d5e50027431f1fdea21c2ebef12944b7842e71eaf",
                    "51210289a43bf822daf338bb07555476a967cc46545a58c513a0badc99861c81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131f6f6a5c88ad9dfedd53f9b52ae",
                    "0100000001d033e1ddf9c44a1402d8dc8d6cfcee634a459537a078359a3c51153b7ba67b220000000001ffffffff02c44b02000000000000001abc76a9141aee120db13f4e4f785aec3da97b48963de58ebd88ac01baaffb0000000000001abc76a914949293b5f8acd5a0a871ce417cd5354d9715a29188ac000000000000000001d00fb2fb00000000000000000000000091483045022100f83aa623b21d302cdc65b6b227fe53f3796379031dd1fee9bc398680f846221d022062282396b391ba38612afea9a648b7db7ef54b0d4b06bddae7783bb25cf6ba1f014751210289a43bf822daf338bb07555476a967cc46545a58c513a0badc99861c81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131f6f6a5c88ad9dfedd53f9b52ae",
                ),
            ]

            for test in tests:
                ticket = msgtx.MsgTx.deserialize(ByteArray(test.ticket))
                keysource = account.KeySource(
                    priv=lambda _: crypto.privKeyFromBytes(ByteArray(test.privKey)),
                    internal=lambda: "",
                )
                redeemScript = ByteArray(test.redeemScript)
                revocation = blockchain.revokeTicket(ticket, keysource, redeemScript)
                self.assertEqual(test.revocation, revocation.txHex())
