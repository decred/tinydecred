"""
Copyright (c) 2019, the Decred developers
See LICENSE for details
"""

import json
import os
from tempfile import TemporaryDirectory

# from decred.util import database
from decred.crypto import crypto, opcode, rando
from decred.dcr import account, nets, txscript
from decred.dcr.vsp import PurchaseInfo, VotingServiceProvider
from decred.dcr.wire import msgblock, msgtx
from decred.util.database import KeyValueDatabase
from decred.util.encode import ByteArray


LOGGER_ID = "test_account"

testSeed = ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b

cryptoKey = crypto.ByteArray(rando.generateSeed(32))

ticketScript = ByteArray("baa914f5618dfc002becfe840da65f6a49457f41d4f21787")

dcrdataTinfo = json.loads(
    """
{
   "status": "immature",
   "purchase_block": {
      "hash": "000000000000000002cf897e7621de5e939e8e2e20da7d3630a2eccb1c27179a",
      "height": 344803
   },
   "maturity_height": 345059,
   "expiration_height": 386019,
   "lottery_block": {
      "hash": "00000000000000000ec419a08a67782f7126dd0750afa8a890d85b2af9663751",
      "height": 350002
   },
   "vote": null,
   "revocation": "69a780b62cf58d23788d5310b549f3b2683ee41846abb901aa89b5dabbe63e6e"
}
"""
)


def test_tinfo(prepareLogger):
    def match(tinfo):
        assert tinfo.status == "immature"
        assert tinfo.purchaseBlock.hash == reversed(
            ByteArray(
                "000000000000000002cf897e7621de5e939e8e2e20da7d3630a2eccb1c27179a"
            )
        )
        assert tinfo.purchaseBlock.height == 344803
        assert tinfo.maturityHeight == 345059
        assert tinfo.expirationHeight == 386019
        assert tinfo.lotteryBlock.hash == reversed(
            ByteArray(
                "00000000000000000ec419a08a67782f7126dd0750afa8a890d85b2af9663751"
            )
        )
        assert tinfo.lotteryBlock.height == 350002
        assert tinfo.vote is None
        assert tinfo.revocation == reversed(
            ByteArray(
                "69a780b62cf58d23788d5310b549f3b2683ee41846abb901aa89b5dabbe63e6e"
            )
        )

    tinfo = account.TicketInfo.parse(dcrdataTinfo)
    match(tinfo)

    tinfoB = tinfo.serialize().b
    reTinfo = account.TicketInfo.unblob(tinfoB)
    match(reTinfo)


dcrdataUTXO = json.loads(
    """
{
    "address": "Dsa3yVGJK9XFx6L5cC8YzcW3M5Q85wdEXcz",
    "txid": "ce4913a7fc91a366ae1ba591bb8315755175917369dcf78a9205d597e73dbe3d",
    "vout": 2,
    "ts": 1581873212,
    "scriptPubKey": "76a91463ae8c6af3c51d3d6e2bb5c5f4be0d623395c5c088ac",
    "height": 424176,
    "amount": 9.42047827,
    "satoshis": 942047827,
    "confirmations": 1
}
"""
)


def newCoinbaseTx():
    tx = msgtx.MsgTx.new()
    # make it a coinbase transaction by adding a zero-hash previous outpoint.
    txIn = msgtx.TxIn(msgtx.OutPoint(ByteArray(length=32), 0, 0))
    tx.addTxIn(txIn)
    return tx


def test_utxo(prepareLogger):
    txid = "ce4913a7fc91a366ae1ba591bb8315755175917369dcf78a9205d597e73dbe3d"

    def match(utxo):
        assert utxo.address == "Dsa3yVGJK9XFx6L5cC8YzcW3M5Q85wdEXcz"
        assert utxo.txHash == reversed(ByteArray(txid))
        assert utxo.vout == 2
        assert utxo.ts == 1581873212
        assert utxo.scriptPubKey == ByteArray(
            "76a91463ae8c6af3c51d3d6e2bb5c5f4be0d623395c5c088ac"
        )
        assert utxo.height == 424176
        assert utxo.satoshis == 942047827
        assert utxo.maturity == 0
        assert utxo.scriptClass == txscript.PubKeyHashTy
        assert utxo.txid == txid
        assert not utxo.isTicket()

    utxo = account.UTXO.parse(dcrdataUTXO)
    match(utxo)

    # test blob/unblob
    utxoB = utxo.serialize().bytes()
    reUTXO = account.UTXO.unblob(utxoB)
    match(reUTXO)

    # set the maturity as a coinbase transaction, which doesn't actually make
    # sense when confirming below, but allows us to test more paths.
    utxo.maturity = utxo.height + nets.mainnet.CoinbaseMaturity

    # create the transaction
    tx = newCoinbaseTx()
    block = msgblock.BlockHeader()
    block.height = 424176
    block.timestamp = 5
    utxo.height = 0
    utxo.ts = 0
    utxo.maturity = 0

    utxo.confirm(block, tx, nets.mainnet)
    assert utxo.height == 424176
    assert utxo.ts == 5
    assert utxo.maturity == 424176 + nets.mainnet.CoinbaseMaturity

    # since its a coinbase is should not be spendable in the next block
    assert not utxo.isSpendable(utxo.height + 1)
    # but it should be spendable after CoinbaseMaturity
    assert utxo.isSpendable(utxo.height + nets.mainnet.CoinbaseMaturity)

    # make it a ticket
    utxo.setTicketInfo(dcrdataTinfo)
    utxo.scriptPubKey = ticketScript
    utxo.parseScriptClass()

    assert utxo.maturity == 345059
    assert utxo.isLiveTicket()
    assert not utxo.isRevocableTicket()
    assert utxo.isTicket()

    utxo.tinfo.status = "missed"
    assert not utxo.isLiveTicket()
    assert utxo.isRevocableTicket()


def test_tiny_block(prepareLogger):
    blockHash = rando.generateSeed(32)
    height = 55
    TinyBlock = account.TinyBlock
    tb1 = TinyBlock(blockHash, height)
    tb2 = TinyBlock.parse(
        {"hash": reversed(ByteArray(blockHash)).hex(), "height": height}
    )
    assert tb1.hash == tb2.hash
    assert tb1.height == tb2.height

    b = tb1.serialize()
    reTB = TinyBlock.unblob(b)
    assert tb1.hash == reTB.hash
    assert tb1.height == reTB.height
    assert tb1 == reTB


def newAccount(db):
    # Create an account key
    xk = crypto.ExtendedKey.new(testSeed)
    dcrKey = xk.deriveCoinTypeKey(nets.mainnet)
    acctKey = dcrKey.deriveAccountKey(0)
    acctKeyPub = acctKey.neuter()
    privKeyEncrypted = crypto.encrypt(cryptoKey, acctKey.serialize())
    pubKeyEncrypted = crypto.encrypt(cryptoKey, acctKeyPub.serialize())
    acct = account.Account(pubKeyEncrypted, privKeyEncrypted, "acctName", "mainnet", db)
    acct.open(cryptoKey, None, None)
    acct.generateGapAddresses()
    return acct


# One utxo for each of external and internal branches.
dcrdataUTXOs = json.loads(
    """
[
    {
        "address": "DsmP6rBEou9Qr7jaHnFz8jTfrUxngWqrKBw",
        "txid": "81a09bd29b6ba770f9968ead531435a3ee586ef21c8240bed2e6fde2e93e351c",
        "vout": 2,
        "ts": 1581886222,
        "scriptPubKey": "76a914f14f995d7b8c37c961bdb1baf431a18026f7e31088ac",
        "height": 424213,
        "satoshis": 942168886,
        "confirmations": 1
    },
    {
        "address": "DskHpgbEb6hqkuHchHhtyojpehFToEtjQSo",
        "txid": "b5c63a179c7caad1cb6e438acd7182f27388fbfb0fe2ecf9843163b627018d5f",
        "vout": 2,
        "ts": 1581886006,
        "scriptPubKey": "76a914f14f995d7b8c37c961bdb1baf431a18026f7e31088ac",
        "height": 424212,
        "satoshis": 942093929,
        "confirmations": 2
    }
]
"""
)

utxoTotal = 942168886 + 942093929


def test_account(prepareLogger):
    """
    Test account functionality.
    """
    with TemporaryDirectory() as tempDir:
        db = KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
        acct = newAccount(db)
        for n in range(20):
            acct.nextExternalAddress()
        satoshis = int(round(5 * 1e8))
        txHash = ByteArray(rando.generateSeed(32))
        txid = reversed(txHash).hex()
        vout = 2
        address = acct.nextExternalAddress()

        utxo = account.UTXO(
            address=address,
            txHash=txHash,
            vout=vout,
            scriptPubKey=ByteArray(0),
            satoshis=satoshis,
            maturity=1,
        )

        # A helper function to get the current utxo count.
        utxocount = lambda: len(list(acct.utxoscan()))

        # Add the utxo
        acct.addUTXO(utxo)
        # Check the count and balance categories.
        assert utxocount() == 1
        assert acct.calcBalance(1).total == satoshis
        assert acct.calcBalance(1).available == satoshis
        assert acct.calcBalance(0).available == 0
        # Helper functions.
        assert acct.caresAboutTxid(txid)
        acct.addUTXO(utxo)
        assert utxocount() == 1
        acct.spendUTXO(utxo)
        assert utxocount() == 0

        b = acct.serialize()
        reAcct = account.Account.unblob(b.b)

        assert acct.pubKeyEncrypted == reAcct.pubKeyEncrypted
        assert acct.privKeyEncrypted == reAcct.privKeyEncrypted
        assert acct.name == reAcct.name
        assert acct.coinID == reAcct.coinID
        assert acct.netID == reAcct.netID
        assert acct.gapLimit == reAcct.gapLimit
        assert acct.cursorExt == reAcct.cursorExt
        assert acct.cursorInt == reAcct.cursorInt
        assert acct.gapLimit == reAcct.gapLimit

        # Create a faux blockchain for the account.
        bctxsForAddr = []
        bcUTXOs = []

        class Blockchain:
            txsForAddr = lambda addr: bctxsForAddr
            UTXOs = lambda addrs: bcUTXOs
            tip = {"height": 5}

        acct.blockchain = Blockchain

        class Signals:
            b = None

            @classmethod
            def balance(cls, b):
                cls.b = b

        acct.signals = Signals

        # Add a txid for this first address
        txid = ByteArray(rando.generateSeed(32)).hex()
        zerothAddr = acct.externalAddresses[0]
        acct.addTxid(zerothAddr, txid)
        # Add a voting service provider
        vspKey = ByteArray(rando.generateSeed(32)).hex()
        ticketAddr = "ticketAddr"
        pi = PurchaseInfo(
            "addr", 1.0, ByteArray(b"scripthashscript"), ticketAddr, 1, 0, 2
        )
        vsp = VotingServiceProvider("https://myvsp.com", vspKey, nets.mainnet.Name, pi)
        acct.setPool(vsp)
        # Add UTXOs
        utxos = [account.UTXO.parse(u) for u in dcrdataUTXOs]
        acct.resolveUTXOs(utxos)

        # Check that the addresses txid and the vsp load from the database.
        acct.txs.clear()
        acct.stakePools.clear()
        acct.utxos.clear()
        assert acct.stakePool() is None
        acct.load(db)
        assert zerothAddr in acct.txs
        assert len(acct.txs[zerothAddr]) == 1
        assert acct.txs[zerothAddr][0] == txid
        assert len(acct.stakePools) == 1
        assert acct.stakePool().apiKey == vspKey
        assert acct.calcBalance().available == utxoTotal
        assert len(acct.getUTXOs(utxoTotal)[0]) == 2
        assert len(acct.getUTXOs(utxoTotal, lambda u: False)[0]) == 0
        assert acct.lastSeen(acct.externalAddresses, -1) == 0
        branch, idx = acct.branchAndIndex(zerothAddr)
        assert branch == account.EXTERNAL_BRANCH
        assert idx == 0
        checkKey = acct.privKey.child(account.EXTERNAL_BRANCH).child(0).key
        assert acct.privKeyForAddress(zerothAddr).key == checkKey
        ticketAddrs = acct.addTicketAddresses([])
        assert len(ticketAddrs) == 1
        assert ticketAddrs[0] == ticketAddr
        assert acct.hasPool()

        # Add a coinbase transaction output to the account.
        coinbase = newCoinbaseTx()
        cbUTXO = account.UTXO("addr", ByteArray(b"id"), 1, height=5, satoshis=int(1e8))
        coinbase.addTxOut(msgtx.TxOut(int(1e8)))
        coinbaseID = coinbase.id()
        cbUTXO.txid = coinbaseID
        acct.addUTXO(cbUTXO)
        acct.addMempoolTx(coinbase)
        assert coinbaseID in acct.mempool
        # Send a block signal and have the transaction confirmed.
        sig = {"message": {"block": {"Tx": [{"TxID": coinbaseID}]}}}
        acct.blockchain.tipHeight = 5
        acct.blockchain.tx = lambda *a: coinbase
        acct.blockSignal(sig)
        assert coinbaseID not in acct.mempool
        assert cbUTXO.key() in acct.utxos
        maturity = 5 + nets.mainnet.CoinbaseMaturity
        assert acct.utxos[cbUTXO.key()].maturity == maturity
        assert acct.calcBalance(maturity).available == utxoTotal + cbUTXO.satoshis
        assert acct.calcBalance(0).available == utxoTotal
        acct.spendUTXOs([cbUTXO])
        assert acct.calcBalance(maturity).available == utxoTotal

        # make a ticket and a vote
        ticket = account.UTXO.parse(dcrdataUTXO)
        utxo.setTicketInfo(dcrdataTinfo)
        utxo.scriptPubKey = ticketScript
        utxo.parseScriptClass()
        acct.addUTXO(ticket)
        expVal = acct.calcBalance().available - ticket.satoshis
        voteTx = msgtx.MsgTx.new()
        voteTx.addTxIn(
            msgtx.TxIn(msgtx.OutPoint(reversed(ByteArray(ticket.txid)), ticket.vout, 0))
        )
        acct.blockchain.tx = lambda *a: voteTx
        acct.addressSignal(ticketAddr, "somehash")
        assert Signals.b.available == expVal

        # Detect a new utxo for the account.
        newVal = int(5e8)
        expVal = acct.calcBalance().available + newVal
        addr = acct.externalAddresses[1]
        a = txscript.decodeAddress(addr, nets.mainnet)
        script = txscript.payToAddrScript(a)
        newTx = msgtx.MsgTx.new()
        op = msgtx.TxOut(newVal, script)
        newTx.addTxOut(op)
        acct.blockchain.tx = lambda *a: newTx
        utxo = account.UTXO(addr, ByteArray(b"txid"), 0, satoshis=newVal)
        acct.blockchain.txVout = lambda *a: utxo
        acct.addressSignal(addr, "somehash")
        assert Signals.b.available == expVal

        # test syncing. add a single output for external address #2
        acct.stakePool().getPurchaseInfo = lambda: None
        acct.stakePool().authorize = lambda a: True
        newVal = int(3e8)
        addr = acct.externalAddresses[2]
        a = txscript.decodeAddress(addr, nets.mainnet)
        script = txscript.payToAddrScript(a)
        newTx = msgtx.MsgTx.new()
        op = msgtx.TxOut(newVal, script)
        newTx.addTxOut(op)
        utxo = account.UTXO(addr, ByteArray(b"txid"), 0, satoshis=newVal)

        def t4a(*a):
            acct.blockchain.txsForAddr = lambda *a: bctxsForAddr
            return [newTx.id()]

        acct.blockchain.txsForAddr = t4a

        def utxos4a(*a):
            acct.blockchain.UTXOs = lambda *a: []
            return [utxo]

        acct.blockchain.UTXOs = utxos4a
        acct.blockchain.subscribeAddresses = lambda addrs: None
        acct.blockchain.subscribeBlocks = lambda a: None
        acct.sync()
        assert Signals.b.available == newVal

        # spend the utxo by sending it. Reusing newTx for convenience.
        changeVal = int(5e7)
        addr = acct.internalAddresses[0]
        change = account.UTXO(addr, ByteArray(b"newtxid"), 0, satoshis=changeVal)
        acct.blockchain.sendToAddress = lambda *a: (newTx, [utxo], [change])
        acct.sendToAddress(1, "recipient")
        assert Signals.b.available == changeVal

        # purchase some tickets. Reusing newTx for convenience again.
        ticket = account.UTXO.parse(dcrdataUTXO)
        ticket.setTicketInfo(dcrdataTinfo)
        ticket.scriptPubKey = ticketScript
        ticket.parseScriptClass()
        acct.blockchain.purchaseTickets = lambda *a: ([newTx, []], [], [ticket])
        acct.purchaseTickets(1, 1)
        assert Signals.b.total == changeVal + ticket.satoshis

        # revoke the ticket
        ticketTx = msgtx.MsgTx.new()
        op = msgtx.TxOut(ticket.satoshis, ticket.scriptPubKey)
        ticketTx.addTxOut(op)
        ticket.tinfo.status = "missed"
        redeemHash = crypto.AddressScriptHash(
            nets.mainnet.ScriptHashAddrID,
            txscript.extractStakeScriptHash(ticketScript, opcode.OP_SSTX),
        )
        acct.stakePool().purchaseInfo.ticketAddress = redeemHash.string()
        revoked = False

        def rev(*a):
            nonlocal revoked
            revoked = True

        acct.blockchain.tx = lambda *a: ticketTx
        acct.blockchain.revokeTicket = rev
        acct.revokeTickets()
        assert revoked


def test_balance(prepareLogger):
    bal = account.Balance(1, 2, 3)
    encoded = account.Balance.blob(bal)
    reBal = account.Balance.unblob(encoded)
    assert bal.available == reBal.available
    assert bal.total == reBal.total
    assert bal.staked == reBal.staked


def test_gap_handling(prepareLogger):
    with TemporaryDirectory() as tempDir:
        db = KeyValueDatabase(os.path.join(tempDir, "tmp.db")).child("tmp")
        internalAddrs = [
            "DskHpgbEb6hqkuHchHhtyojpehFToEtjQSo",
            "Dsm4oCLnLraGDedfU5unareezTNT75kPbRb",
            "DsdN6A9bWhKKJ7PAGdcDLxQrYPKEnjnDv2N",
            "Dsifz8eRHvQrfaPXgHHLMDHZopFJq2pBPU9",
            "DsmmzJiTTmpafdt2xx7LGk8ZW8cdAKe53Zx",
            "DsVB47P4N23PK5C1RyaJdqkQDzVuCDKGQbj",
            "DsouVzScdUUswvtCAv6nxRzi2MeufpWnELD",
            "DsSoquT5SiDPfksgnveLv3r524k1v8RamYm",
            "DsbVDrcfhbdLy4YaSmThmWN47xhxT6FC8XB",
            "DsoSrtGYKruQLbvhA92xeJ6eeuAR1GGJVQA",
        ]

        externalAddrs = [
            "DsmP6rBEou9Qr7jaHnFz8jTfrUxngWqrKBw",
            "DseZQKiWhN3ceBwDJEgGhmwKD3fMbwF4ugf",
            "DsVxujP11N72PJ46wgU9sewptWztYUy3L7o",
            "DsYa4UBo379cRMCTpDLxYVfpMvMNBdAGrGS",
            "DsVSEmQozEnsZ9B3D4Xn4H7kEedDyREgc18",
            "DsifDp8p9mRocNj7XNNhGAsYtfWhccc2cry",
            "DsV78j9aF8NBwegbcpPkHYy9cnPM39jWXZm",
            "DsoLa9Rt1L6qAVT9gSNE5F5XSDLGoppMdwC",
            "DsXojqzUTnyRciPDuCFFoKyvQFd6nQMn7Gb",
            "DsWp4nShu8WxefgoPej1rNv4gfwy5AoULfV",
        ]

        account.DefaultGapLimit = gapLimit = 5
        acct = newAccount(db)
        acct.gapLimit = gapLimit

        listsAreEqual = lambda a, b: len(a) == len(b) and all(
            x == y for x, y in zip(a, b)
        )

        watchAddrs = internalAddrs[:gapLimit] + externalAddrs[: gapLimit + 1]
        assert len(acct.watchAddrs()) == len(watchAddrs)
        assert set(acct.watchAddrs()) == set(watchAddrs)
        assert listsAreEqual(acct.internalAddresses, internalAddrs[:gapLimit])

        # The external branch starts with the "last seen" at the zeroth address, so
        # has one additional address to start.
        assert listsAreEqual(acct.externalAddresses, externalAddrs[: gapLimit + 1])

        # Open the account to generate addresses.
        acct.open(cryptoKey, None, None)
        acct.addTxid(internalAddrs[0], "C4fA6958A1847D")
        newAddrs = acct.generateGapAddresses()
        assert len(newAddrs) == 1
        assert newAddrs[0] == internalAddrs[5]

        # The zeroth external address is considered "seen", so this should not
        # change anything.
        acct.addTxid(externalAddrs[0], "C4fA6958A1847D")
        newAddrs = acct.generateGapAddresses()
        assert len(newAddrs) == 0

        # Mark the 1st address as seen.
        acct.addTxid(externalAddrs[1], "C4fA6958A1847D")
        newAddrs = acct.generateGapAddresses()
        assert len(newAddrs) == 1
        assert externalAddrs[1] == acct.currentAddress()

        # cursor should be at index 0, last seen 1, max index 6, so calling
        # nextExternalAddress 5 time should put the cursor at index 6, which is
        # the gap limit.
        for i in range(5):
            acct.nextExternalAddress()
        assert acct.currentAddress() == externalAddrs[6]

        # one more should wrap the cursor back to 1, not zero, so the current
        # address is lastSeenExt(=1) + cursor(=1) = 2
        a1 = acct.nextExternalAddress()
        assert acct.currentAddress() == externalAddrs[2]
        assert a1 == acct.currentAddress()

        # Sanity check that internal addresses are wrapping too.
        for i in range(20):
            acct.nextInternalAddress()
        addrs = acct.internalAddresses
        assert addrs[len(addrs) - 1] == internalAddrs[5]
