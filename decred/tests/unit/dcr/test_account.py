"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import json

import pytest

from decred import DecredError
from decred.crypto import crypto, opcode, rando
from decred.dcr import account, nets, txscript
from decred.dcr.vsp import PurchaseInfo, VotingServiceProvider
from decred.dcr.wire import msgblock, msgtx
from decred.util.database import KeyValueDatabase
from decred.util.encode import ByteArray


LOGGER_ID = "test_account"

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


def test_unblob_check():
    data = {0: 1}
    # Unsupported version.
    with pytest.raises(NotImplementedError):
        account.unblob_check("test", 1, 0, data)
    # Unexpected pushes.
    with pytest.raises(DecredError):
        account.unblob_check("test", 0, 2, data)
    # No errors.
    assert account.unblob_check("test", 0, 1, data) is None


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
    assert utxo.isImmatureTicket()
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
    testSeed = ByteArray(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).b
    xk = crypto.ExtendedKey.new(testSeed)
    dcrKey = xk.deriveCoinTypeKey(nets.mainnet)
    acctKey = dcrKey.deriveAccountKey(0)
    acctKeyPub = acctKey.neuter()
    privKeyEncrypted = crypto.encrypt(cryptoKey, acctKey.serialize())
    pubKeyEncrypted = crypto.encrypt(cryptoKey, acctKeyPub.serialize())
    return account.Account(pubKeyEncrypted, privKeyEncrypted, "acctName", "mainnet", db)


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


def test_account():
    """
    Test account functionality.
    """
    db = KeyValueDatabase(":memory:").child("tmp")
    acct = newAccount(db)
    acct.unlock(cryptoKey)
    acct.generateGapAddresses()
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
    class Blockchain:
        txsForAddr = lambda addr: []
        UTXOs = lambda addrs: []
        tipHeight = 5

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
    pi = PurchaseInfo("addr", 1.0, ByteArray(b"scripthashscript"), ticketAddr, 1, 0, 2)
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
    acct.load(db, Blockchain, Signals)
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
        acct.blockchain.txsForAddr = lambda *a: []
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
    acct.signals.spentTickets = lambda: True
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


def test_account_unlock(monkeypatch):
    def mock_privateKey(self):
        raise crypto.CrazyKeyError

    monkeypatch.setattr(crypto.ExtendedKey, "privateKey", mock_privateKey)
    db = KeyValueDatabase(":memory:").child("tmp")
    acct = newAccount(db)
    assert not acct.isUnlocked()
    with pytest.raises(DecredError):
        acct.unlock(cryptoKey)


def test_balance(prepareLogger):
    bal = account.Balance(1, 2, 3)
    encoded = account.Balance.blob(bal)
    reBal = account.Balance.unblob(encoded)
    assert bal.available == reBal.available
    assert bal.total == reBal.total
    assert bal.staked == reBal.staked


def test_gap_handling():
    db = KeyValueDatabase(":memory:").child("tmp")
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
    acct.unlock(cryptoKey)
    acct.generateGapAddresses()
    acct.gapLimit = gapLimit

    listsAreEqual = lambda a, b: len(a) == len(b) and all(x == y for x, y in zip(a, b))

    watchAddrs = internalAddrs[:gapLimit] + externalAddrs[: gapLimit + 1]
    assert len(acct.watchAddrs()) == len(watchAddrs)
    assert set(acct.watchAddrs()) == set(watchAddrs)
    assert listsAreEqual(acct.internalAddresses, internalAddrs[:gapLimit])

    # The external branch starts with the "last seen" at the zeroth address, so
    # has one additional address to start.
    assert listsAreEqual(acct.externalAddresses, externalAddrs[: gapLimit + 1])

    # Open the account to generate addresses.
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


def test_ticket_info_from_spending_tx():
    """
    Test constructing tinfo from spending tx.
    """
    ticket = (
        "0100000002387a5b26700b9780f745921f14694e6563fe9a855d322ad4"
        "01cea43cddb816d80200000000ffffffff387a5b26700b9780f745921f"
        "14694e6563fe9a855d322ad401cea43cddb816d80300000000ffffffff"
        "05c47b008801000000000018baa9143068cdfb98fd1eb27ac708e933f2"
        "f9286c27ef0d8700000000000000000000206a1e781f472a926da0bb7c"
        "e9eec7f4d434de21015cae80ff01000000000000580000000000000000"
        "00001abd76a914000000000000000000000000000000000000000088ac"
        "00000000000000000000206a1e90875ba5fee5f35352e9171d40190e79"
        "6b1b15277091fe87010000000058000000000000000000001abd76a914"
        "000000000000000000000000000000000000000088ac00000000000000"
        "000280ff01000000000048700500020000006b483045022100a4e0e625"
        "ce3d0f0d80477d64d439071cd52875ad8eecac0a164a224552cdbe1d02"
        "204e0f71975fdc5d26ff8740e98fff3f630f739ebcf82c9373419207ce"
        "cc92a56701210392d0251eddee688fb0bf0140cd32f66e0c2328fa0193"
        "195aa44ccad345b3c0797091fe870100000048700500020000006a4730"
        "440220016ea7d98cd3adb826bae11ccd0caec2cb23ecabf42424eedd5c"
        "83ab6f0d6cbe02206684c1f2c38b61f9da7faa0b2bf9d802c5f07ec7be"
        "a31729d6ec2cc55a3476de01210392d0251eddee688fb0bf0140cd32f6"
        "6e0c2328fa0193195aa44ccad345b3c079"
    )

    revocation = (
        "010000000139cb023fdcf6fcd18273c7395f51084721d0e4baf0ca"
        "3ee9590ad63a411a4cb30000000001ffffffff02f0ff0100000000"
        "0000001abc76a914781f472a926da0bb7ce9eec7f4d434de21015c"
        "ae88ac8fcc07ba0100000000001abc76a914f90abbb67dc9257efa"
        "6ab24eb88e2755f34b1f7f88ac0000000000000000018ad609ba01"
        "000000296505001000000091483045022100bc9a694d0864df030e"
        "6edea181a2e2385dfbf93396b5792899a65f19c9afd67a02206052"
        "192b5631e062f4497706276ec514a14cdfa8035ef6c7dca0df7120"
        "84618e0147512103af3c24d005ca8b755e7167617f3a5b4c60a65f"
        "8318a7fcd1b0cacb1abd2a97fc21027b81bc16954e28adb8322481"
        "40eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae"
    )

    lotteryBlkHeader = (
        "08000000f5fff7b1daf5d81bdb0dcf0e57b53366353d720d"
        "97f965f9ec9723c341000000af1e5cbae4064bd50e4f82a9"
        "5ba38176c113c5b8a3aaf73195674a787485e5ab7fd2076e"
        "365a895a677a16e8a08ba63fad2a89f42042adf3032ef9e2"
        "d65ada8e0100823a94a9e54105001002311400006a7e621d"
        "f99a21c501000000866d05003f1d000040a8335e0fe3cc00"
        "2e6492202536b13a00000000000000000000000000000000"
        "000000000000000008000000"
    )

    purchaseBlkHeader = (
        "08000000c605a843366b64d669f277d9142533ef4e339ac"
        "f192b5fae281d8b49010000003028d68834c31dd387a7e4"
        "a5b2df6316013788819ed61f4f0f5f4da56d6d86e6a25df"
        "e5a736252237f85db2e0298c72f03d091fa4987fd6ab4e2"
        "ea9087dd877801002b72bd5a29d405001400ad140000001"
        "b761d8ad609ba0100000029650500903300004ec12f5ee3"
        "9319002de4b8299d2f99400000000000000000000000000"
        "0000000000000000000000008000000"
    )

    class FakeTicketInfo(account.TicketInfo):
        def __init__(self):
            pass

    ti = FakeTicketInfo()

    pbh = msgblock.BlockHeader.deserialize(ByteArray(purchaseBlkHeader))
    tinyP = account.TinyBlock(pbh.cachedHash(), pbh.height)
    rev = msgtx.MsgTx.deserialize(ByteArray(revocation))
    lbh = msgblock.BlockHeader.deserialize(ByteArray(lotteryBlkHeader))
    tinyL = account.TinyBlock(lbh.cachedHash(), lbh.height)
    ticket = msgtx.MsgTx.deserialize(ticket)

    tinfo = ti.fromSpendingTx(ticket, rev, tinyP, tinyL, nets.testnet)

    assert tinfo.status == "revoked"
    assert tinfo.purchaseBlock.height == 353577
    assert tinfo.maturityHeight == 353593
    assert tinfo.expirationHeight == 359737
    assert tinfo.lotteryBlock.height == 355718
    assert tinfo.vote is None
    assert tinfo.revocation == rev.txid()
    assert tinfo.poolFee == 131056
    assert tinfo.purchaseTxFee == 5420
    assert tinfo.spendTxFee == 2571
    assert tinfo.stakebase == 0

    ticket = (
        "0100000002bde648ee89dec1e687f2ddcab3ddce2953717c47f8716923"
        "e35bd06a4351f81d0000000000ffffffffbde648ee89dec1e687f2ddca"
        "b3ddce2953717c47f8716923e35bd06a4351f81d0100000000ffffffff"
        "058ad609ba01000000000018baa9143068cdfb98fd1eb27ac708e933f2"
        "f9286c27ef0d8700000000000000000000206a1e781f472a926da0bb7c"
        "e9eec7f4d434de21015caefb0902000000000000580000000000000000"
        "00001abd76a914000000000000000000000000000000000000000088ac"
        "00000000000000000000206a1ef90abbb67dc9257efa6ab24eb88e2755"
        "f34b1f7fbbe107ba010000000058000000000000000000001abd76a914"
        "000000000000000000000000000000000000000088ac00000000000000"
        "0002fb0902000000000028650500050000006b483045022100b42aefb8"
        "9eca6a4608115f48de20f6574337085bdff5cb8dbc04cb52ec71986e02"
        "2036f12f662381cd6f0e920380d881a3191ad834a02721dfcd9b2b9f32"
        "266073460121028c4e667b51128332036daf75d46f1a1e9115eaf4c086"
        "e0b2b94d91e855ba1754bbe107ba0100000028650500050000006b4830"
        "45022100c912cb3bddb732047011730805ea8fb42017ef1865fda8c22d"
        "c9423fc9be2e65022022aa0bc735f1624277ee71e0e77cf24f211689cf"
        "39e73467cc1e82712ccd53b20121028c4e667b51128332036daf75d46f"
        "1a1e9115eaf4c086e0b2b94d91e855ba1754"
    )

    vote = (
        "010000000200000000000000000000000000000000000000000000000000"
        "00000000000000ffffffff00ffffffff571ce9fb0c52ae22c3a6480cbf6d"
        "30ff76bdffbf54b6e081eb218aa3a0ca2bc40000000001ffffffff040000"
        "0000000000000000266a2432c0c546b332f7abf51f3fc73f4482185f4c09"
        "61625763a766774237280000007f75050000000000000000000000086a06"
        "050008000000900102000000000000001abb76a914781f472a926da0bb7c"
        "e9eec7f4d434de21015cae88acd9b293890100000000001abb76a9149087"
        "5ba5fee5f35352e9171d40190e796b1b152788ac000000000000000002a6"
        "3895010000000000000000ffffffff020000c47b00880100000049700500"
        "0600000091483045022100c1ec49cb687fa2421e76b534ced49563b3de1e"
        "c6407b1bbfda26752fbdedc88302204988390ea3be77324909781322a46b"
        "463d00dd14718f0964b9536b5eef4e35570147512103af3c24d005ca8b75"
        "5e7167617f3a5b4c60a65f8318a7fcd1b0cacb1abd2a97fc21027b81bc16"
        "954e28adb832248140eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae"
    )

    lotteryBlkHeader = (
        "0800000032c0c546b332f7abf51f3fc73f4482185f4c0961"
        "625763a7667742372800000077270b229ee8e9be0a96bf14"
        "c01797cb4af8e104115be3669898c0a7d319a31fe66e45e4"
        "5c94392225a2ca6ffec424fb60d1adfc8c23259624ce949b"
        "3740ed2b0100e507395f6e5905000000a61400005ea3001e"
        "d11d24a101000000807505006c080000e96e375e6000fd00"
        "cd4f3e1dc861c7db00000000000000000000000000000000"
        "000000000000000008000000"
    )

    purchaseBlkHeader = (
        "080000001bb464c806d08ff2d3970a0aa3e23357b815e23"
        "e50bdc21dca341a2929000000688c46a5bb4400340dd4c0"
        "0ef2074f2cbfc01b75365abf72370bafa35f27f52324a3c"
        "6c4fc58e54a66bc5d595eac4c82c212312276c681590c19"
        "7c702b4e88f70100bc0a7cbc436e0500060080130000aa7"
        "3741dc47b00880100000049700500ae26000064fa345e9d"
        "8b2d00b3c9521b11e06aff0000000000000000000000000"
        "0000000000000000000000008000000"
    )

    pbh = msgblock.BlockHeader.deserialize(ByteArray(purchaseBlkHeader))
    tinyP = account.TinyBlock(pbh.cachedHash(), pbh.height)
    lbh = msgblock.BlockHeader.deserialize(ByteArray(lotteryBlkHeader))
    tinyL = account.TinyBlock(lbh.cachedHash(), lbh.height)
    ticket = msgtx.MsgTx.deserialize(ticket)
    v = msgtx.MsgTx.deserialize(vote)

    tinfo = ti.fromSpendingTx(ticket, v, tinyP, tinyL, nets.testnet)

    assert tinfo.status == "voted"
    assert tinfo.purchaseBlock.height == 356425
    assert tinfo.maturityHeight == 356441
    assert tinfo.expirationHeight == 362585
    assert tinfo.lotteryBlock.height == 357760
    assert tinfo.vote == v.txid()
    assert tinfo.revocation is None
    assert tinfo.poolFee == 131472
    assert tinfo.purchaseTxFee == 5420
    assert tinfo.spendTxFee == 1
    assert tinfo.stakebase == 26556582

    tinfo = ti.fromSpendingTx(ticket, v, tinyP, None, nets.testnet)

    assert tinfo.status == "unconfirmed"
    assert tinfo.purchaseBlock.height == 356425
    assert tinfo.maturityHeight == 356441
    assert tinfo.expirationHeight == 362585
    assert tinfo.lotteryBlock is None
    assert tinfo.vote == v.txid()
    assert tinfo.revocation is None
    assert tinfo.poolFee == 131472
    assert tinfo.purchaseTxFee == 5420
    assert tinfo.spendTxFee == 1
    assert tinfo.stakebase == 26556582


def test_utxo_ticket_from_tx():
    stakeSubmission = ByteArray(opcode.OP_SSTX)
    stakeSubmission += opcode.OP_HASH160
    stakeSubmission += opcode.OP_DATA_20
    stakeSubmission += 1 << (8 * 19)
    stakeSubmission += opcode.OP_EQUAL

    tx = msgtx.MsgTx.new()
    tx.txOut = [msgtx.TxOut(pkScript=stakeSubmission, value=3)]
    ticket = account.UTXO.ticketFromTx(tx, nets.testnet)
    assert ticket.tinfo.status == "mempool"
    tinfo = account.TicketInfo("no_status", None, 0, 0, None, None, None)
    ticket = account.UTXO.ticketFromTx(tx, nets.testnet, None, tinfo)
    assert ticket.tinfo.status == "unconfirmed"


def test_account_update_spent_tickets():
    """
    Test updating spent tickets.
    """

    class Dummy:
        pass

    class FakeAccount(account.Account):
        def __init__(self):
            self.signals = Dummy()
            pool = Dummy()
            pool.purchaseInfo = Dummy()
            pool.purchaseInfo.ticketAddress = "ticketaddress"
            self.stakePools = [pool]
            self.blockchain = Dummy()
            self.mempool = {}
            self.txs = {}
            self.utxos = {}
            self.net = nets.testnet

    db = KeyValueDatabase(":memory:").child("tmp")

    acct = FakeAccount()
    tDB = acct.ticketDB = db.child(
        "tickets", datatypes=("TEXT", "BLOB"), blobber=account.UTXO
    )

    def fail():
        assert False

    acct.signals.spentTickets = fail

    # tickets and ticketDB empty, noop
    acct.updateSpentTickets()

    stakeSubmission = ByteArray(opcode.OP_SSTX)
    stakeSubmission += opcode.OP_HASH160
    stakeSubmission += opcode.OP_DATA_20
    stakeSubmission += 1 << (8 * 19)
    stakeSubmission += opcode.OP_EQUAL

    def newTinfo(status="live"):
        return account.TicketInfo(
            status=status,
            purchaseBlock=account.TinyBlock(ByteArray(0), 42),
            maturityHeight=0,
            expirationHeight=0,
            lotteryBlock=None,
            vote=None,
            revocation=None,
            poolFee=0,
            purchaseTxFee=1,
            spendTxFee=0,
            stakebase=0,
        )

    txid = "aa"

    def utxoWithTxid(txid):
        return account.UTXO(
            address="ticketaddress",
            txHash=reversed(ByteArray(txid)),
            vout=0,
            scriptPubKey=stakeSubmission,
            satoshis=2,
            tinfo=newTinfo(),
        )

    utxo = utxoWithTxid(txid)

    def txWithTxid(txid):
        txInOne = msgtx.TxIn(msgtx.OutPoint(ByteArray("ff"), 0, 0), valueIn=1)
        txInTwo = msgtx.TxIn(None, valueIn=3)
        txOutOne = msgtx.TxOut(pkScript=stakeSubmission, value=3)
        txOutTwo = msgtx.TxOut()
        txOutThree = msgtx.TxOut()
        txOutFour = msgtx.TxOut()
        txOutFive = msgtx.TxOut()
        txsIn = [txInOne, txInTwo]
        txsOut = [txOutOne, txOutTwo, txOutThree, txOutFour, txOutFive]
        return msgtx.MsgTx(
            reversed(ByteArray(txid)), None, None, txsIn, txsOut, None, None
        )

    tx = txWithTxid(txid)
    utxo.tinfo.status = "mempool"
    tDB[txid] = utxo
    acct.mempool[txid] = tx

    # mempool and ticketDB have the same txid and status, noop
    acct.updateSpentTickets()

    called = False

    def ok():
        nonlocal called
        called = True

    acct.signals.spentTickets = ok

    tinfos = {
        "aa": utxo.tinfo,
        "ab": newTinfo(),
        "ac": newTinfo(),
        "ad": newTinfo(),
        "ae": newTinfo(status="unconfirmed"),
    }

    txs = {k: txWithTxid(k) for k in tinfos.keys() if k != "ab"}

    blockheader = Dummy()
    blockheader.height = 0
    blockheader.timestamp = 0

    vote = "ff"
    revocation = "fe"

    def setVoteOrRevoke(txid):
        if txid == vote:
            ticket = tDB["ac"]
            ticket.tinfo.vote = reversed(ByteArray(vote))
        if txid == revocation:
            ticket = tDB["ad"]
            ticket.tinfo.revocation = reversed(ByteArray(revocation))

    acct.spendTicket = lambda tx: setVoteOrRevoke(reversed(tx.cachedH).hex())
    acct.blockchain.tx = lambda txid: txs[txid]
    acct.blockchain.ticketInfo = lambda txid: tinfos[txid]
    acct.blockchain.blockForTx = lambda *args: blockheader
    acct.utxos = {k + "#0": utxoWithTxid(k) for k in txs.keys()}
    acct.mempool = {"ab": txWithTxid("ab")}

    txs[vote] = txWithTxid(vote)
    txs[revocation] = txWithTxid(revocation)

    # Live tickets are now different than database.
    acct.updateSpentTickets()
    assert called

    # The tickets are now stored in the database.
    assert "ab" in tDB and "ac" in tDB and "ad" in tDB
    # They are unspent tickets.
    ut = acct.unspentTickets()
    assert "ab" in ut and "ac" in ut and "ad" in ut

    called = False
    txid = "ac"
    tinfos["ac"].vote = reversed(ByteArray(vote))
    del acct.utxos[txid + "#0"]

    # A ticket has been voted.
    acct.updateSpentTickets()
    assert called
    # It is an voted ticket.
    assert txid in acct.votedTickets() and txid not in acct.unspentTickets()

    called = False
    txid = "ad"
    tinfos["ad"].revocation = reversed(ByteArray(revocation))
    del acct.utxos[txid + "#0"]

    # A ticket has been revoked.
    acct.updateSpentTickets()
    assert called
    # It is a revoked ticket.
    assert txid in acct.revokedTickets() and txid not in acct.unspentTickets()

    txid = "af"
    called = False
    tDB[txid] = utxo

    # A txid is in the ticketDB but not in utxos or mempool or the
    # blockchain.
    acct.updateSpentTickets()
    assert called
    # It was removed.
    assert txid not in tDB


def test_account_calc_ticket_profits():
    """
    Test ticket profit calculation.
    """

    class FakeAccount(account.Account):
        def __init__(self):
            pass

    db = KeyValueDatabase(":memory:").child("tmp")

    acct = FakeAccount()
    tDB = acct.ticketDB = db.child(
        "tickets", datatypes=("TEXT", "BLOB"), blobber=account.UTXO
    )

    def newTinfo(poolFee, purchaseTxFee, spendTxFee, stakebase):
        return account.TicketInfo(
            status="",
            purchaseBlock=account.TinyBlock(ByteArray(0), 0),
            maturityHeight=0,
            expirationHeight=0,
            lotteryBlock=None,
            vote=None,
            revocation=None,
            poolFee=poolFee,
            purchaseTxFee=purchaseTxFee,
            spendTxFee=spendTxFee,
            stakebase=stakebase,
        )

    utxo = account.UTXO(
        address="",
        txHash=reversed(ByteArray("aa")),
        vout=0,
        scriptPubKey=None,
        satoshis=5,
    )

    tinfo = newTinfo(0, 1, 1, 1)
    utxo.tinfo = tinfo
    tDB["aa"] = utxo
    tinfo = newTinfo(1, 1, 1, 1)
    utxo.tinfo = tinfo
    tDB["ab"] = utxo
    tinfo = newTinfo(0, 1, 0, 0)
    utxo.tinfo = tinfo
    tDB["ac"] = utxo

    stakebases, poolFees, txFees = acct.calcTicketProfits()

    s, p, t = 2, 1, 5

    assert stakebases == s
    assert poolFees == p
    assert txFees == t


def test_account_spend_ticket():
    """
    Test updating spent tickets.
    """
    vote = (
        "010000000200000000000000000000000000000000000000000000000000"
        "00000000000000ffffffff00ffffffff571ce9fb0c52ae22c3a6480cbf6d"
        "30ff76bdffbf54b6e081eb218aa3a0ca2bc40000000001ffffffff040000"
        "0000000000000000266a2432c0c546b332f7abf51f3fc73f4482185f4c09"
        "61625763a766774237280000007f75050000000000000000000000086a06"
        "050008000000900102000000000000001abb76a914781f472a926da0bb7c"
        "e9eec7f4d434de21015cae88acd9b293890100000000001abb76a9149087"
        "5ba5fee5f35352e9171d40190e796b1b152788ac000000000000000002a6"
        "3895010000000000000000ffffffff020000c47b00880100000049700500"
        "0600000091483045022100c1ec49cb687fa2421e76b534ced49563b3de1e"
        "c6407b1bbfda26752fbdedc88302204988390ea3be77324909781322a46b"
        "463d00dd14718f0964b9536b5eef4e35570147512103af3c24d005ca8b75"
        "5e7167617f3a5b4c60a65f8318a7fcd1b0cacb1abd2a97fc21027b81bc16"
        "954e28adb832248140eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae"
    )

    revocation = (
        "010000000139cb023fdcf6fcd18273c7395f51084721d0e4baf0ca"
        "3ee9590ad63a411a4cb30000000001ffffffff02f0ff0100000000"
        "0000001abc76a914781f472a926da0bb7ce9eec7f4d434de21015c"
        "ae88ac8fcc07ba0100000000001abc76a914f90abbb67dc9257efa"
        "6ab24eb88e2755f34b1f7f88ac0000000000000000018ad609ba01"
        "000000296505001000000091483045022100bc9a694d0864df030e"
        "6edea181a2e2385dfbf93396b5792899a65f19c9afd67a02206052"
        "192b5631e062f4497706276ec514a14cdfa8035ef6c7dca0df7120"
        "84618e0147512103af3c24d005ca8b755e7167617f3a5b4c60a65f"
        "8318a7fcd1b0cacb1abd2a97fc21027b81bc16954e28adb8322481"
        "40eb58bedb6078ae5f4dabf21fde5a8ab7135cb652ae"
    )

    # Tickets can be found on testnet3.
    ticketVotedTxid = "c42bcaa0a38a21eb81e0b654bfffbd76ff306dbf0c48a6c322ae520cfbe91c57"
    ticketRevokedTxid = (
        "b34c1a413ad60a59e93ecaf0bae4d0214708515f39c77382d1fcf6dc3f02cb39"
    )

    voteTxid = "aa19094e404a1ee056760bdb1b7ed1b6c8e5f1d97752335eddbfdfa19e76c262"
    revocationTxid = "d85694ba7aae060667b393558cd96c2df2926426f80db16a18bf4fc9102b0953"

    class Dummy:
        pass

    class FakeAccount(account.Account):
        def __init__(self):
            self.signals = Dummy()
            self.blockchain = Dummy()
            self.net = nets.testnet

    db = KeyValueDatabase(":memory:").child("tmp")

    acct = FakeAccount()
    tDB = acct.ticketDB = db.child(
        "tickets", datatypes=("TEXT", "BLOB"), blobber=account.UTXO
    )

    def newTinfo(status):
        return account.TicketInfo(
            status=status,
            purchaseBlock=account.TinyBlock(ByteArray(0), 0),
            maturityHeight=0,
            expirationHeight=0,
        )

    utxo = account.UTXO(
        address="",
        txHash=reversed(ByteArray("aa")),
        vout=0,
        scriptPubKey=None,
        satoshis=5,
    )

    txidToTinfo = {
        voteTxid: newTinfo("vote"),
        revocationTxid: newTinfo("revocation"),
    }
    acct.blockchain.ticketInfoForSpendingTx = lambda txid, net: txidToTinfo[txid]

    tDB[ticketVotedTxid] = utxo
    tDB[ticketRevokedTxid] = utxo

    v = msgtx.MsgTx.deserialize(ByteArray(vote))

    acct.spendTicket(v)
    tinfo = tDB[ticketVotedTxid].tinfo
    assert tinfo.status == "vote"

    rev = msgtx.MsgTx.deserialize(ByteArray(revocation))

    acct.spendTicket(rev)
    tinfo = tDB[ticketRevokedTxid].tinfo
    assert tinfo.status == "revocation"
