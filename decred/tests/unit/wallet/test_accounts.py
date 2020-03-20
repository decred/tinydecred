"""
Copyright (c) 2019-2020, the Decred developers
See LICENSE for details
"""

import pytest

from decred import DecredError
from decred.crypto import crypto, rando
from decred.dcr import nets
from decred.util import chains, database, encode
from decred.wallet import accounts


testSeed = encode.ByteArray(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
).b

tRoot = crypto.ExtendedKey.new(testSeed)


def test_child_neuter(prepareLogger):
    """
    Test the ExtendedKey.neuter method.
    """
    extKey = crypto.ExtendedKey.new(testSeed)
    extKey.setNetwork(nets.mainnet)
    extKey.child(0)
    pub = extKey.neuter()
    expStr = (
        "dpubZ9169KDAEUnyo8vdTJcpFWeaUEKH3G6detaXv46HxtQcENwxGBbRqbfTCJ9BUnWP"
        + "CkE8WApKPJ4h7EAapnXCZq1a9AqWWzs1n31VdfwbrQk"
    )
    assert pub.string() == expStr


def test_change_addresses(prepareLogger):
    """
    Test internal branch address derivation.
    """
    cryptoKey = rando.newKey()
    db = database.KeyValueDatabase(":memory:").child("tmp")
    # ticker for coin type is ok. Case insensitive.
    acctMgr = accounts.createNewAccountManager(
        tRoot, cryptoKey, "DcR", nets.mainnet, db
    )
    acct = acctMgr.openAccount(0, cryptoKey)
    for i in range(10):
        acct.nextInternalAddress()


def test_account_manager(prepareLogger):
    cryptoKey = rando.newKey()
    db = database.KeyValueDatabase(":memory:").child("tmp")
    # 42 = Decred
    acctMgr = accounts.createNewAccountManager(tRoot, cryptoKey, 42, nets.mainnet, db)

    acct = acctMgr.openAccount(0, cryptoKey)
    tempAcct = acctMgr.addAccount(cryptoKey, "temp")
    assert acctMgr.account(1) == tempAcct
    assert acctMgr.listAccounts() == [acct, tempAcct]
    acctMgr.accounts[3] = tempAcct
    del acctMgr.accounts[1]
    with pytest.raises(DecredError):
        acctMgr.listAccounts()
    del acctMgr.accounts[3]

    with pytest.raises(DecredError):
        accounts.AccountManager.unblob(encode.BuildyBytes(0))

    zeroth = acct.currentAddress()
    b = acctMgr.serialize()
    reAM = accounts.AccountManager.unblob(b.b)

    assert acctMgr.coinType == reAM.coinType
    assert acctMgr.netName == reAM.netName
    assert acctMgr.netName == reAM.netName

    reAM.load(db, None)
    reAcct = reAM.openAccount(0, cryptoKey)
    reZeroth = reAcct.currentAddress()

    assert zeroth == reZeroth


def test_discover(prepareLogger):
    cryptoKey = rando.newKey()
    db = database.KeyValueDatabase(":memory:").child("tmp")
    acctMgr = accounts.createNewAccountManager(
        tRoot, cryptoKey, "dcr", nets.mainnet, db
    )
    txs = {}

    class Blockchain:
        params = nets.mainnet
        addrsHaveTxs = lambda addrs: any(a in txs for a in addrs)

    ogChain = chains.chain("dcr")
    chains.registerChain("dcr", Blockchain)
    ogLimit = accounts.ACCOUNT_GAP_LIMIT
    accounts.ACCOUNT_GAP_LIMIT = 2

    acctMgr.discover(cryptoKey)
    assert len(acctMgr.accounts) == 1

    coinExtKey = acctMgr.coinKey(cryptoKey)
    acct2ExtKey = coinExtKey.deriveAccountKey(2).neuter().child(0)
    acct2Addr5 = acct2ExtKey.deriveChildAddress(5, nets.mainnet)
    txs[acct2Addr5] = ["tx"]
    acctMgr.discover(cryptoKey)
    assert len(acctMgr.accounts) == 3

    chains.registerChain("dcr", ogChain)
    accounts.ACCOUNT_GAP_LIMIT = ogLimit
