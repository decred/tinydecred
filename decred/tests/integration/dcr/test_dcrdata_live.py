"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import time

from decred.crypto import crypto, rando
from decred.crypto.secp256k1 import curve as Curve
from decred.dcr import account, dcrdata, txscript
from decred.dcr.nets import mainnet, testnet
from decred.dcr.wire import msgtx
from decred.util.encode import ByteArray


class TestDcrdata:
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
        client.close()

    def test_get_block_header(self):
        blockchain = dcrdata.DcrdataBlockchain(
            ":memory:", mainnet, "https://alpha.dcrdata.org"
        )
        try:
            blockchain.connect()
            blockchain.blockHeader(
                "298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980"
            )
        finally:
            blockchain.close()

    def test_purchase_ticket(self):
        blockchain = dcrdata.DcrdataBlockchain(
            ":memory:", testnet, "https://testnet.dcrdata.org"
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
                    addr = crypto.AddressPubKeyHash(testnet.PubKeyHashAddrID, pkHash)
                    addrs.append(addr)
                    addrString = addr.string()
                    keys[addrString] = privKey
                    pkScript = txscript.makePayToAddrScript(addrString, testnet)
                    txHash = rando.newHash()
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
            scriptAddr = crypto.AddressScriptHash(testnet.ScriptHashAddrID, scriptHash)
            ticketPrice = blockchain.stakeDiff()

            request = account.TicketRequest(
                minConf=0,
                expiry=0,
                spendLimit=ticketPrice * 2 * 1.1,
                poolAddress=poolAddr.string(),
                votingAddress=scriptAddr.string(),
                ticketFee=0,
                poolFees=7.5,
                count=2,
                txFee=0,
            )

            ticket, spent, newUTXOs = blockchain.purchaseTickets(
                KeySource(), utxosource, request
            )
        finally:
            blockchain.close()

    def test_revoke_ticket(self):
        blockchain = dcrdata.DcrdataBlockchain(
            ":memory:", testnet, "https://testnet.dcrdata.org"
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
                "010000000210fd1f5623e2469d9bb390ad21b12f6710f5d6be0e130df074cf"
                "d8614d0c4e050400000000ffffffff10fd1f5623e2469d9bb390ad21b12f67"
                "10f5d6be0e130df074cfd8614d0c4e050500000000ffffffff05508f4a7401"
                "000000000018baa91438a8a93737e62e806f49d1465518a02f110d57fe8700"
                "000000000000000000206a1e1aee120db13f4e4f785aec3da97b48963de58e"
                "bd37570200000000000058000000000000000000001abd76a9140000000000"
                "00000000000000000000000000000088ac00000000000000000000206a1eab"
                "c7372997a530b43e8e17a4850602b28e0768dd454d48740100000000580000"
                "00000000000000001abd76a914000000000000000000000000000000000000"
                "000088ac000000000000000002375702000000000000000000000000006a47"
                "304402202b5f4a97abf78d95875de75b244f9b4c7f60bb40b01a9188133102"
                "2a03a3bf32022047f951e0414e4f28518b5254974abeb93f77727bee7c6fbd"
                "5010f8bf375dd10f012102ec908402cb3ab128a9a68978fbb3b33f1c97d715"
                "afb8f76dbbe300619878f095454d48740100000000000000000000006a4730"
                "4402200435095049ac7b3f3c47a43d92afc22db032b929357f2f216eb24e91"
                "cd0d2d2802203ca93654cc1f193f11ce0c7e74f9959edd984c15d54f99b0d2"
                "27b1cdd99a4a3e012102ec908402cb3ab128a9a68978fbb3b33f1c97d715af"
                "b8f76dbbe300619878f095",
                #
                "d407f81cb789e65579590d5e50027431f1fdea21c2ebef12944b7842e71eaf",
                #
                "51210289a43bf822daf338bb07555476a967cc46545a58c513a0badc99861c"
                "81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131f6f6a5c8"
                "8ad9dfedd53f9b52ae",
                #
                "0100000001113d36ae0156c1f5a3071de1f7f10e9e4521a77266b1927f832b"
                "abb9fe3d5cd90000000001ffffffff022c4d02000000000000001abc76a914"
                "1aee120db13f4e4f785aec3da97b48963de58ebd88ac193848740100000000"
                "001abc76a914abc7372997a530b43e8e17a4850602b28e0768dd88ac000000"
                "000000000001508f4a740100000000000000000000009148304502210099b8"
                "e13022e13d19229fff3a2b08ebf54f5cd4ea79c85618d04a57a735283e9102"
                "203e0fd5a66a168edff1bbcaeaa9d5b2d5e224cbd5d90a6c0099c73810d749"
                "3924014751210289a43bf822daf338bb07555476a967cc46545a58c513a0ba"
                "dc99861c81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131"
                "f6f6a5c88ad9dfedd53f9b52ae",
            ),
            test(
                "010000000228a301cae233e252143e6fff3ccd348e156bbcc8ea158cfb4a1f"
                "e19f78cad1e80a00000000ffffffff28a301cae233e252143e6fff3ccd348e"
                "156bbcc8ea158cfb4a1fe19f78cad1e80b00000000ffffffff05d00fb2fb00"
                "000000000018baa91438a8a93737e62e806f49d1465518a02f110d57fe8700"
                "000000000000000000206a1e1aee120db13f4e4f785aec3da97b48963de58e"
                "bdcf550200000000000058000000000000000000001abd76a9140000000000"
                "00000000000000000000000000000088ac00000000000000000000206a1e94"
                "9293b5f8acd5a0a871ce417cd5354d9715a2912dcfaffb0000000000580000"
                "00000000000000001abd76a914000000000000000000000000000000000000"
                "000088ac000000000000000002cf5502000000000000000000000000006b48"
                "3045022100a4072a6a09058cf1b2713b75e636bcdf418c9897aa18cd584cfc"
                "f0229bf6b7d102200cb94cfef85a31943ab1e0daba90578c3b465be26e4a94"
                "a19e1da5ec70586193012103ac3936e6c8d0fd9cefde6cc9552289c943a1eb"
                "4abe1601de8f8e46b8f7ed508d2dcfaffb0000000000000000000000006a47"
                "304402202fc0578332b69746109066cc7d7cb9b86f0a693639bbe4dc84c83f"
                "26ef0e3bad022010ad57133bcc77bb36600488679f5da6ab6740b4d743470b"
                "cd60f2ecda70aa7f012103ac3936e6c8d0fd9cefde6cc9552289c943a1eb4a"
                "be1601de8f8e46b8f7ed508d",
                #
                "d407f81cb789e65579590d5e50027431f1fdea21c2ebef12944b7842e71eaf",
                #
                "51210289a43bf822daf338bb07555476a967cc46545a58c513a0badc99861c"
                "81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131f6f6a5c8"
                "8ad9dfedd53f9b52ae",
                #
                "0100000001d033e1ddf9c44a1402d8dc8d6cfcee634a459537a078359a3c51"
                "153b7ba67b220000000001ffffffff02c44b02000000000000001abc76a914"
                "1aee120db13f4e4f785aec3da97b48963de58ebd88ac01baaffb0000000000"
                "001abc76a914949293b5f8acd5a0a871ce417cd5354d9715a29188ac000000"
                "000000000001d00fb2fb00000000000000000000000091483045022100f83a"
                "a623b21d302cdc65b6b227fe53f3796379031dd1fee9bc398680f846221d02"
                "2062282396b391ba38612afea9a648b7db7ef54b0d4b06bddae7783bb25cf6"
                "ba1f014751210289a43bf822daf338bb07555476a967cc46545a58c513a0ba"
                "dc99861c81f985782103b1f62148c92802a47ce98a49d1f14f397adc759131"
                "f6f6a5c88ad9dfedd53f9b52ae",
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
            assert test.revocation == revocation.txHex()
