import os
import pytest

from decred.btc.btcwallet import btcwallet
from decred.btc.nets import mainnet
from decred.btc import addrlib
from decred.btc.wire import msgtx
from decred.crypto.secp256k1.curve import PrivateKey
from decred.util.encode import ByteArray

import json


def decAddr(a):
    return addrlib.decodeAddress(a, mainnet)


@pytest.fixture(scope='session', autouse=True)
def rig(request):

    class rig:
        data = None
        wallet = None

    libDir = os.path.dirname(os.path.realpath(btcwallet.__file__))
    dataPath = os.path.join(libDir, "libbtcwallet", "test-data.json")
    with open(dataPath, "r") as f:
        rig.data = json.loads(f.read())
    rig.wallet = btcwallet.BTCWallet(
        walletDir=dataPath,
        netParams=mainnet,
        feeder=lambda obj: print(obj),
        debugLevel=1,
        test=True,
    )
    return rig


def test_MakeMultiSigScript(rig):
    addr1 = decAddr(rig.data["MakeMultiSigScript.in.addr.1"])
    addr2 = decAddr(rig.data["MakeMultiSigScript.in.addr.2"])
    nConfs = rig.data["MakeMultiSigScript.in.nConfs"]
    script = rig.wallet.makeMultiSigScript([addr1, addr2], nConfs)
    assert script == ByteArray(rig.data["MakeMultiSigScript.out"])


def test_ImportP2SHRedeemScript(rig):
    script = rig.data["ImportP2SHRedeemScript.in.script"]
    addr = rig.wallet.importP2SHRedeemScript(ByteArray(script))
    assert addr == rig.data["ImportP2SHRedeemScript.out.addr"]


def test_UnspentOutputs(rig):
    acct = rig.data["ImportP2SHRedeemScript.in.acct"]
    confs = rig.data["ImportP2SHRedeemScript.in.confs"]

    outputs = rig.wallet.unspentOutputs(btcwallet.OutputSelectionPolicy(acct, confs))
    assert len(outputs) == 1

    txo = outputs[0]

    assert txo.outPoint.hash == ByteArray(rig.data["ImportP2SHRedeemScript.out.outPoint.hash"])
    assert txo.outPoint.index == rig.data["ImportP2SHRedeemScript.out.outPoint.index"]
    assert txo.output.pkScript == rig.data["ImportP2SHRedeemScript.out.output.script"]
    assert txo.output.value == rig.data["ImportP2SHRedeemScript.out.output.value"]
    assert txo.outputKind == rig.data["ImportP2SHRedeemScript.out.outputKind"]
    assert txo.containingBlock.hash == rig.data["ImportP2SHRedeemScript.out.containingBlock.hash"]
    assert txo.containingBlock.height == rig.data["ImportP2SHRedeemScript.out.containingBlock.index"]
    assert txo.receiveTime == rig.data["ImportP2SHRedeemScript.out.receiveTime"]

    txHash = ByteArray(rig.data["LockedOutpoint.in.hash"])
    idx = rig.data["LockedOutpoint.in.index"]
    locked = rig.wallet.lockedOutpoint(msgtx.OutPoint(
        txHash=txHash,
        idx=idx,
    ))
    assert locked == rig.data["LockedOutpoint.out.locked"]

    ops = rig.wallet.lockedOutpoints()
    assert len(ops) == 1
    assert ops[0].hash == rig.data["LockedOutpoints.out.hash"]

    txHash = ByteArray(rig.data["LeaseOutput.in.hash"])
    idx = rig.data["LeaseOutput.in.index"]
    lockID = ByteArray(rig.data["LeaseOutput.in.lockID"])
    expiration = rig.wallet.leaseOutput(lockID=lockID, op=msgtx.OutPoint(
        txHash=txHash,
        idx=idx,
    ))
    assert expiration == rig.data["LeaseOutput.out"]

    # looking for panics
    txHash = ByteArray(rig.data["LockOutpoint.in.hash"])
    idx = rig.data["LockOutpoint.in.index"]
    rig.wallet.lockOutpoint(msgtx.OutPoint(
        txHash=txHash,
        idx=idx,
    ))
    txHash = ByteArray(rig.data["UnlockOutpoint.in.hash"])
    idx = rig.data["UnlockOutpoint.in.index"]
    rig.wallet.unlockOutpoint(msgtx.OutPoint(
        txHash=txHash,
        idx=idx,
    ))
    txHash = ByteArray(rig.data["ReleaseOutput.in.hash"])
    idx = rig.data["ReleaseOutput.in.index"]
    lockID = ByteArray(rig.data["ReleaseOutput.in.lockID"])
    expiration = rig.wallet.releaseOutput(lockID=lockID, op=msgtx.OutPoint(
        txHash=txHash,
        idx=idx,
    ))


def test_simpleMethods(rig):
    # Single-valued returns
    assert rig.wallet.shuttingDown() == rig.data["ShuttingDown.out"]
    assert rig.wallet.synchronizingToNetwork() == rig.data["SynchronizingToNetwork.out"]
    assert rig.wallet.chainSynced() == rig.data["ChainSynced.out"]
    assert rig.wallet.locked() == rig.data["Locked.out"]
    assert rig.wallet.haveAddress(decAddr(rig.data["HaveAddress.in"])) == rig.data["HaveAddress.out"]
    assert rig.wallet.accountOfAddress(decAddr(rig.data["AccountOfAddress.in.addr"])) == rig.data["AccountOfAddress.out.acct"]

    # Look for exceptions/panics with these
    rig.wallet.setChainSynced(rig.data["SetChainSynced.in"])
    rig.wallet.start()
    rig.wallet.stop()
    rig.wallet.waitForShutdown()
    rig.wallet.unlock(rig.data["Unlock.in.passphrase"], 123)
    rig.wallet.lock()
    rig.wallet.labelTransaction(
        h=ByteArray(rig.data["LabelTransaction.in.h"]),
        label=rig.data["LabelTransaction.in.label"],
        overwrite=rig.data["LabelTransaction.in.overwrite"],
    )


def test_passphraseChanges(rig):
    rig.wallet.changePrivatePassphrase(
        old=rig.data["ChangePrivatePassphrase.in.old"],
        new=rig.data["ChangePrivatePassphrase.in.new"],
    )
    rig.wallet.changePublicPassphrase(
        old=rig.data["ChangePublicPassphrase.in.old"],
        new=rig.data["ChangePublicPassphrase.in.new"],
    )
    rig.wallet.changePassphrases(
        publicOld=rig.data["ChangePassphrases.in.publicOld"],
        publicNew=rig.data["ChangePassphrases.in.publicNew"],
        privateOld=rig.data["ChangePassphrases.in.privateOld"],
        privateNew=rig.data["ChangePassphrases.in.privateNew"],
    )


def test_MsgTx_methods(rig):
    authoredTx = rig.wallet.createSimpleTx(
        acct=rig.data["CreateSimpleTx.in.acct"],
        outputs=[msgtx.TxOut(
            value=rig.data["CreateSimpleTx.in.output.value"],
            pkScript=ByteArray(rig.data["CreateSimpleTx.in.output.script"]),
            version=rig.data["CreateSimpleTx.in.output.version"],
        )],
        minConf=rig.data["CreateSimpleTx.in.minConf"],
        satPerKb=rig.data["CreateSimpleTx.in.satPerKb"],
        dryRun=rig.data["CreateSimpleTx.in.dryRun"],
    )

    expTx = msgtx.MsgTx.deserialize(ByteArray(rig.data["CreateSimpleTx.out.tx"]))
    assert expTx == authoredTx.tx

    assert len(authoredTx.prevScripts) == 1
    assert authoredTx.prevScripts[0] == ByteArray(rig.data["CreateSimpleTx.out.prevScript"])

    assert len(authoredTx.prevInputValues) == 1
    assert authoredTx.prevInputValues[0] == rig.data["CreateSimpleTx.out.prevInputValue"]

    assert authoredTx.totalInput == rig.data["CreateSimpleTx.out.totalInput"]
    assert authoredTx.changeIndex == rig.data["CreateSimpleTx.out.changeIndex"]

    value = rig.data["SendOutputs.in.value"]
    pkScript = ByteArray(rig.data["SendOutputs.in.pkScript"])
    acct = rig.data["SendOutputs.in.acct"]
    minConf = rig.data["SendOutputs.in.minconf"]
    satPerKb = rig.data["SendOutputs.in.satPerKb"]
    label = rig.data["SendOutputs.in.label"]
    tx = rig.wallet.sendOutputs(
        outputs=[msgtx.TxOut(value=value, pkScript=pkScript)],
        acct=acct,
        minConf=minConf,
        satPerKb=satPerKb,
        label=label,
    )
    assert tx.serialize() == rig.data["SendOutputs.out.tx"]

    tx = msgtx.MsgTx.deserialize(ByteArray(rig.data["SignTransaction.in.tx"]))
    hashType = rig.data["SignTransaction.in.hashType"]
    prevoutHash = ByteArray(rig.data["SignTransaction.in.prevout.hash"])
    prevoutIdx = rig.data["SignTransaction.in.prevout.idx"]
    prevoutScript = ByteArray(rig.data["SignTransaction.in.prevout.script"])
    keyAddr = rig.data["SignTransaction.in.key.addr"]
    keyWIF = addrlib.WIF.decode(rig.data["SignTransaction.in.key.wif"])
    scriptAddr = rig.data["SignTransaction.in.script.addr"]
    redeemScript = ByteArray(rig.data["SignTransaction.in.script.script"])
    rig.wallet.signTransaction(
        tx=tx,
        hashType=hashType,
        additionalPrevScripts={f"{prevoutHash.rhex()}:{prevoutIdx}": prevoutScript},  # Dict[str, ByteArray],  # key is outpoint ID txid:index, e.g. a27e1f:1
        additionalKeysByAddress={keyAddr: keyWIF},
        p2shRedeemScriptsByAddress={scriptAddr: redeemScript},
    )
    assert tx.txIn[0].signatureScript == rig.data["SignTransaction.out.sigScript"]

    tx = msgtx.MsgTx.deserialize(ByteArray(rig.data["PublishTransaction.in.tx"]))
    label = rig.data["PublishTransaction.in.label"]
    rig.wallet.publishTransaction(tx=tx, label=label)


def test_account_methods(rig):
    addrs = rig.wallet.accountAddresses(rig.data["AccountAddresses.in.acct"])
    assert len(addrs) == 2
    assert addrs[0].string() == rig.data["AccountAddresses.out.addr.1"]
    assert addrs[1].string() == rig.data["AccountAddresses.out.addr.2"]

    acct = rig.data["CurrentAddress.in.acct"]
    purpose = rig.data["CurrentAddress.in.purpose"]
    coin = rig.data["CurrentAddress.in.coin"]
    addr = rig.wallet.currentAddress(acct=acct, scope=btcwallet.KeyScope(purpose=purpose, coin=coin))
    assert addr.string() == rig.data["CurrentAddress.out.addr"]

    purpose = rig.data["AccountNumber.in.scope.purpose"]
    coin = rig.data["AccountNumber.in.scope.coin"]
    acctName = rig.data["AccountNumber.in.accountName"]
    acct = rig.wallet.accountNumber(accountName=acctName, scope=btcwallet.KeyScope(purpose=purpose, coin=coin))
    assert acct == rig.data["AccountNumber.out.acct"]

    purpose = rig.data["AccountName.in.scope.purpose"]
    coin = rig.data["AccountName.in.scope.coin"]
    acct = rig.data["AccountName.in.acct"]
    acctName = rig.wallet.accountName(accountNumber=acct, scope=btcwallet.KeyScope(purpose=purpose, coin=coin))
    assert acctName == rig.data["AccountName.out.accountName"]

    purpose = rig.data["AccountProperties.in.scope.purpose"]
    coin = rig.data["AccountProperties.in.scope.coin"]
    acct = rig.data["AccountProperties.in.acct"]
    acctProps = rig.wallet.accountProperties(accountNumber=acct, scope=btcwallet.KeyScope(purpose=purpose, coin=coin))
    assert acctProps.accountNumber == rig.data["AccountProperties.out.accountNumber"]
    assert acctProps.accountName == rig.data["AccountProperties.out.accountName"]
    assert acctProps.externalKeyCount == rig.data["AccountProperties.out.externalKeyCount"]
    assert acctProps.internalKeyCount == rig.data["AccountProperties.out.internalKeyCount"]
    assert acctProps.importedKeyCount == rig.data["AccountProperties.out.importedKeyCount"]

    purpose = rig.data["RenameAccount.in.scope.purpose"]
    coin = rig.data["RenameAccount.in.scope.coin"]
    acct = rig.data["RenameAccount.in.acct"]
    newName = rig.data["RenameAccount.in.newName"]
    rig.wallet.renameAccount(
        accountNumber=acct,
        newName=newName,
        scope=btcwallet.KeyScope(purpose=purpose, coin=coin),
    )

    purpose = rig.data["Accounts.in.purpose"]
    coin = rig.data["Accounts.in.coin"]
    acctsResult = rig.wallet.accounts(scope=btcwallet.KeyScope(purpose=purpose, coin=coin))
    assert acctsResult.currentBlockHash == ByteArray(rig.data["Accounts.out.blockHash"])
    assert acctsResult.currentBlockHeight == rig.data["Accounts.out.blockHeight"]
    assert len(acctsResult.accounts) == 1
    account = acctsResult.accounts[0]
    assert account.totalBalance == rig.data["Accounts.out.balance"]
    assert account.accountNumber == rig.data["Accounts.out.acct"]

    confs = rig.data["AccountBalances.in.confs"]
    purpose = rig.data["AccountBalances.in.purpose"]
    coin = rig.data["AccountBalances.in.coin"]
    bals = rig.wallet.accountBalances(
        requiredConfs=confs,
        scope=btcwallet.KeyScope(purpose=purpose, coin=coin),
    )
    assert len(bals) == 1
    bal = bals[0]
    assert bal.accountNumber == rig.data["AccountBalances.out.acctNumber"]
    assert bal.accountName == rig.data["AccountBalances.out.acctName"]
    assert bal.accountBalance == rig.data["AccountBalances.out.balance"]

    minConf = rig.data["ListUnspent.in.minConf"]
    maxConf = rig.data["ListUnspent.in.maxConf"]
    addr = rig.data["ListUnspent.in.addr"]
    unspents = rig.wallet.listUnspent(minConf=minConf, maxConf=maxConf, addresses=[addr])
    assert len(unspents) == 1
    assert unspents[0].scriptPubKey == rig.data["ListUnspent.out.scriptPubKey"]

    addrs = rig.wallet.sortedActivePaymentAddresses()
    assert len(addrs) == 1
    assert addrs[0] == rig.data["SortedActivePaymentAddresses.out"]

    purpose = rig.data["NewAddress.in.purpose"]
    coin = rig.data["NewAddress.in.coin"]
    acct = rig.data["NewAddress.in.acct"]
    addr = rig.wallet.newAddress(
        acct=acct,
        scope=btcwallet.KeyScope(purpose=purpose, coin=coin),
    )
    assert addr.string() == rig.data["NewAddress.out.addr"]

    purpose = rig.data["NewChangeAddress.in.purpose"]
    coin = rig.data["NewChangeAddress.in.coin"]
    acct = rig.data["NewChangeAddress.in.acct"]
    addr = rig.wallet.newChangeAddress(
        acct=acct,
        scope=btcwallet.KeyScope(purpose=purpose, coin=coin),
    )
    assert addr.string() == rig.data["NewChangeAddress.out.addr"]

    purpose = rig.data["TotalReceivedForAccounts.in.purpose"]
    coin = rig.data["TotalReceivedForAccounts.in.coin"]
    minConf = rig.data["TotalReceivedForAccounts.in.minConf"]
    accts = rig.wallet.totalReceivedForAccounts(
        scope=btcwallet.KeyScope(purpose=purpose, coin=coin),
        minConf=minConf,
    )
    assert len(accts) == 1
    acct = accts[0]
    assert acct.accountNumber == rig.data["TotalReceivedForAccounts.out.accountNumber"]
    assert acct.accountName == rig.data["TotalReceivedForAccounts.out.accountName"]
    assert acct.totalReceived == rig.data["TotalReceivedForAccounts.out.totalReceived"]
    assert acct.lastConfirmation == rig.data["TotalReceivedForAccounts.out.lastConfirmation"]

    addr = decAddr(rig.data["TotalReceivedForAddr.in.addr"])
    minConf = rig.data["TotalReceivedForAddr.in.minConf"]
    amt = rig.wallet.totalReceivedForAddr(addr=addr, minConf=minConf)
    assert amt == rig.data["TotalReceivedForAddr.out.amt"]


def test_listTx_methods(rig):
    start = rig.data["ListSinceBlock.in.start"]
    end = rig.data["ListSinceBlock.in.end"]
    syncHeight = rig.data["ListSinceBlock.in.syncHeight"]
    txs = rig.wallet.listSinceBlock(start=start, end=end, syncHeight=syncHeight)
    assert len(txs) == 1
    assert txs[0].blockTime == rig.data["ListSinceBlock.out.blockTime"]

    skip = rig.data["ListTransactions.in.skip"]
    count = rig.data["ListTransactions.in.count"]
    txs = rig.wallet.listTransactions(skip=skip, count=count)
    assert len(txs) == 1
    assert txs[0].confirmations == rig.data["ListTransactions.out.confs"]

    addr = rig.data["ListAddressTransactions.in.addr"]
    txs = rig.wallet.listAddressTransactions(addrs=[addr])
    assert len(txs) == 1
    assert txs[0].timeReceived == rig.data["ListAddressTransactions.out.timeReceived"]

    txs = rig.wallet.listAllTransactions()
    assert len(txs) == 1
    assert txs[0].vout == rig.data["ListAllTransactions.out.vout"]


def test_Balances(rig):
    bal = rig.wallet.calculateBalance(rig.data["CalculateBalance.in.confirms"])
    assert bal == rig.data["CalculateBalance.out"]

    bals = rig.wallet.calculateAccountBalances(
        acct=rig.data["CalculateAccountBalances.in.acct"],
        confirms=rig.data["CalculateAccountBalances.in.confirms"],
    )

    assert bals.total == rig.data["CalculateAccountBalances.out.total"]
    assert bals.spendable == rig.data["CalculateAccountBalances.out.spendable"]
    assert bals.immatureReward == rig.data["CalculateAccountBalances.out.immatureReward"]


def test_KeyMethods(rig):
    addr = decAddr(rig.data["PubKeyForAddress.in.addr"])
    pubKey = rig.wallet.pubKeyForAddress(addr)
    assert pubKey.serializeCompressed() == rig.data["PubKeyForAddress.out.pubkey"]

    addr = decAddr(rig.data["PrivKeyForAddress.in.addr"])
    privKey = rig.wallet.privKeyForAddress(addr)
    assert privKey.key == rig.data["PrivKeyForAddress.out.privkey"]

    keys = rig.wallet.dumpPrivKeys()
    assert len(keys) == 1
    assert keys[0].key == rig.data["DumpPrivKeys.out"]

    addr = decAddr(rig.data["DumpWIFPrivateKey.in.addr"])
    wif = rig.wallet.dumpWIFPrivateKey(addr)
    assert wif.privKey.key == rig.data["DumpWIFPrivateKey.out.priv"]

    purpose = rig.data["ImportPrivateKey.in.purpose"]
    coin = rig.data["ImportPrivateKey.in.coin"]
    priv = PrivateKey.fromBytes(ByteArray(rig.data["ImportPrivateKey.in.priv"]))
    blockHeight = rig.data["ImportPrivateKey.in.blockHeight"]
    blockHash = ByteArray(rig.data["ImportPrivateKey.in.blockHash"])
    blockStamp = rig.data["ImportPrivateKey.in.blockStamp"]
    rescan = rig.data["ImportPrivateKey.in.rescan"]
    wif = addrlib.WIF(privKey=priv, compressPubKey=True, netID=mainnet)
    addr = rig.wallet.importPrivateKey(
        scope=btcwallet.KeyScope(purpose=purpose, coin=coin),
        wif=wif,
        bs=btcwallet.BlockStamp(
            height=blockHeight,
            blockHash=blockHash,
            timeStamp=blockStamp,
        ),
        rescan=rescan,
    )

    assert addr == rig.data["ImportPrivateKey.out.addr"]


def test_addressInfo(rig):
    addr = decAddr(rig.data["AddressInfo.in.addr"])
    mgAddr = rig.wallet.addressInfo(addr)

    assert mgAddr.acct == rig.data["AddressInfo.out.acct"]
    assert mgAddr.addr == rig.data["AddressInfo.out.addr"]
    assert mgAddr.addrHash == ByteArray(rig.data["AddressInfo.out.addrHash"])
    assert mgAddr.imported == rig.data["AddressInfo.out.imported"]
    assert mgAddr.internal == rig.data["AddressInfo.out.internal"]
    assert mgAddr.compressed == rig.data["AddressInfo.out.compressed"]
    assert mgAddr.addrType == rig.data["AddressInfo.out.addrType"]
