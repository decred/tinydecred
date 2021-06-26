import json
from typing import Callable, Dict, List, Optional, Union

from decred.crypto.secp256k1.curve import curve as Curve, PublicKey, PrivateKey
from decred import DecredError
from decred.btc import addrlib
from decred.btc.wire import msgtx
from decred.btc.btcwallet.golink import Go, registerFeeder
from decred.util.encode import ByteArray


JSONType = Union[str, int, float, bool, None, Dict[str, 'JSONType'], List['JSONType']]


class WalletException(DecredError):
    def __init__(self, e):
        """
        Virtually any error from the Go side will be returned as a WalletException.
        """
        super().__init__(e["error"])


def isError(e):
    """
    All messages pass through a single interface. If any error is encountered
    while running the specified command on the Go side, the response will have
    a non-nil "error" property.
    """
    return isinstance(e, dict) and e.get("error")


class OutputSelectionPolicy:
    def __init__(self, acct: int, requiredConfs: int):
        self.account = acct
        self.requiredConfs = requiredConfs


class BlockIdentity:
    def __init__(self, blockHash: ByteArray, blockHeight: int):
        self.hash = blockHash
        self.height = blockHeight


class TransactionOutput:
    def __init__(
        self,
        outPoint: msgtx.OutPoint,
        output: msgtx.TxOut,
        outputKind: int,
        containingBlock: BlockIdentity,
        receiveTime: int,
    ):
        self.outPoint = outPoint
        self.output = output
        self.outputKind = outputKind
        self.containingBlock = containingBlock
        self.receiveTime = receiveTime


class Balances:
    def __init__(self, total: int, spendable: int, immatureReward: int):
        self.total = total
        self.spendable = spendable
        self.immatureReward = immatureReward


class AuthoredTx:
    def __init__(
        self,
        tx: msgtx.MsgTx,
        prevScripts: List[ByteArray],
        prevInputValues: List[int],
        totalInput: int,
        changeIndex: int,
    ):
        self.tx = tx
        self.prevScripts = prevScripts
        self.prevInputValues = prevInputValues
        self.totalInput = totalInput
        self.changeIndex = changeIndex


class KeyScope:
    def __init__(self, purpose: int, coin: int):
        self.purpose = purpose
        self.coin = coin

    def dict(self) -> dict:
        return dict(
            coin=self.coin,
            purpose=self.purpose,
        )


KeyScopeBIP0044 = KeyScope(44, 0)


def parseScope(scope):
    return scope.dict() if scope else KeyScopeBIP0044.dict()


class ManagedAddress:
    def __init__(
        self,
        acct: int,
        addr: addrlib.Address,
        addrHash: ByteArray,
        imported: bool,
        internal: bool,
        compressed: bool,
        addrType: int,
    ):
        self.acct = acct
        self.addr = addr
        self.addrHash = addrHash
        self.imported = imported
        self.internal = internal
        self.compressed = compressed
        self.addrType = addrType


class AccountProperties:
    def __init__(
        self,
        accountNumber: int,
        accountName: str,
        externalKeyCount: int,
        internalKeyCount: int,
        importedKeyCount: int,
    ):
        self.accountNumber = accountNumber
        self.accountName = accountName
        self.externalKeyCount = externalKeyCount
        self.internalKeyCount = internalKeyCount
        self.importedKeyCount = importedKeyCount


class ListTransactionsResult:
    def __init__(
        self,
        abandoned: bool,
        account: str,
        amount: int,
        category: str,
        confirmations: int,
        time: int,
        timeReceived: int,
        trusted: bool,
        txid: str,
        vout: int,
        address: Optional[Union[addrlib.Address, None]] = None,
        bip125: Optional[str] = "",
        blockHash: Optional[Union[ByteArray, None]] = None,
        blockHeight: Optional[Union[int, None]] = None,
        blockIndex: Optional[Union[int, None]] = None,
        blockTime:  Optional[Union[int, None]] = None,
        fee: Optional[int] = 0,
        generated: Optional[Union[bool, None]] = None,
        involvesWatchOnly: Optional[Union[bool, None]] = None,
        label: Optional[Union[str, None]] = None,
        walletConflicts: Optional[Union[List[str], None]] = None,
        comment: Optional[Union[str, None]] = None,
        otherAccount: Optional[Union[str, None]] = None,
    ):

        self.abandoned = abandoned
        self.account = account
        self.address = address
        self.amount = amount
        self.bip125 = bip125
        self.blockHash = blockHash
        self.blockHeight = blockHeight
        self.blockIndex = blockIndex
        self.blockTime = blockTime
        self.category = category
        self.confirmations = confirmations
        self.fee = fee
        self.generated = generated
        self.involvesWatchOnly = involvesWatchOnly
        self.label = label
        self.time = time
        self.timeReceived = timeReceived
        self.trusted = trusted
        self.txid = txid
        self.vout = vout
        self.walletConflicts = walletConflicts
        self.comment = comment
        self.otherAccount = otherAccount


class AccountResult(AccountProperties):
    def __init__(self, totalBalance: int, **k):
        super().__init__(**k)
        self.totalBalance = totalBalance


class AccountsResult:
    def __init__(
        self,
        accounts: List[AccountResult],
        currentBlockHash: ByteArray,
        currentBlockHeight: int,
    ):
        self.accounts = accounts
        self.currentBlockHash = currentBlockHash
        self.currentBlockHeight = currentBlockHeight


class AccountBalanceResult:
    def __init__(
        self,
        accountNumber: int,
        accountName: str,
        accountBalance: int,
    ):
        self.accountNumber = accountNumber
        self.accountName = accountName
        self.accountBalance = accountBalance


class ListUnspentResult:
    def __init__(
        self,
        txid: str,
        vout: int,
        address: addrlib.Address,
        account: str,
        scriptPubKey: ByteArray,
        amount: int,
        confirmations: int,
        spendable: bool,
        redeemScript: Optional[Union[ByteArray, None]] = None,
    ):
        self.txid = txid
        self.vout = vout
        self.address = address
        self.account = account
        self.scriptPubKey = scriptPubKey
        self.amount = amount
        self.confirmations = confirmations
        self.spendable = spendable
        self.redeemScript = redeemScript


class BlockStamp:
    def __init__(
        self,
        height: int,
        blockHash: ByteArray,
        timeStamp: int,
    ):
        self.height = height
        self.blockHash = blockHash
        self.timeStamp = timeStamp

    def dict(self) -> dict:
        return dict(
            height=self.height,
            hash=self.blockHash.hex(),
            timestamp=self.timeStamp,
        )


class AccountTotalReceivedResult:
    def __init__(
        self,
        accountNumber: int,
        accountName: str,
        totalReceived: int,
        lastConfirmation: int,
    ):
        self.accountNumber = accountNumber
        self.accountName = accountName
        self.totalReceived = totalReceived
        self.lastConfirmation = lastConfirmation


class SyncStatus:
    def __init__(self, target: int, height: int, syncing: bool):
        self.target = target
        self.height = height
        self.syncing = syncing

    def dict(self):
        return dict(
            target=self.target,
            height=self.height,
            syncing=self.syncing,
        )


def WalletExists(walletDir: str, net: object) -> bool:
    if hasattr(net, "Name"):
        net = net.Name
    return Go("walletExists", dict(
        net=net,
        dir=walletDir,
    ))


def CreateWallet(seed: ByteArray, pw: ByteArray, walletDir: str, netParams: object):
    res = Go('createWallet', dict(
        pw=pw.hex(),
        seed=seed.hex(),
        dir=walletDir,
        net=netParams.Name,
    ))
    if isError(res):
        raise WalletException(res)


class BTCWallet:
    """
    BTCWallet is a Bitcoin wallet that works based on C bindings to
    github.com/btcsuite/btcwallet.

    All methods are named identically to the btcwallet.Wallet counterparts, with
    the exception that the leading letter is lower-cased.
    """
    def __init__(
        self,
        walletDir: str,
        netParams: object,
        feeder: Callable[[JSONType], None],
        debugLevel: Optional[int] = 3,  # Info
        connectPeers: Optional[Union[List[str], None]] = None,
        test: Optional[bool] = False,
    ):
        self.netParams = netParams
        self.feeder = feeder
        registerFeeder(self.feed)
        self.go("init", dict(
            dir=walletDir,
            net=netParams.Name,
            logLevel=debugLevel,  # Debug
            connectPeers=connectPeers,
            test=test,
        ))

    def feed(self, msg: ByteArray):
        msg["symbol"] = "btc"
        self.feeder(msg)

    def go(self, func: str, thing: Optional[JSONType] = "") -> JSONType:
        res = Go(func, thing)
        if isError(res):
            raise WalletException(res)
        return res

    def makeMultiSigScript(self, addrs: List[addrlib.Address], nRequired: int) -> ByteArray:
        hexScript = self.go("makeMultiSigScript", dict(
            addrs=[a.string() for a in addrs],
            nRequired=nRequired,
        ))
        return ByteArray(hexScript)

    def importP2SHRedeemScript(self, script: ByteArray) -> addrlib.AddressScriptHash:
        addrStr = self.go("importP2SHRedeemScript", script.hex())
        return addrlib.decodeAddress(addrStr, self.netParams)

    def unspentOutputs(self, policy: OutputSelectionPolicy) -> List[TransactionOutput]:
        res = self.go("unspentOutputs", dict(account=policy.account, requiredConfirmations=policy.requiredConfs))
        outputs = []
        for to in res:
            outPt = to["outPoint"]
            op = to["output"]
            blk = to["containingBlock"]

            outputs.append(TransactionOutput(
                outPoint=msgtx.OutPoint(
                    txHash=ByteArray(outPt["hash"]),
                    idx=outPt["index"],
                ),
                output=msgtx.TxOut(
                    value=op["value"],
                    pkScript=ByteArray(op["script"]),
                ),
                outputKind=to["outputKind"],
                containingBlock=BlockIdentity(
                    blockHash=blk["hash"],
                    blockHeight=blk["index"],
                ),
                receiveTime=to["receiveTime"],
            ))

        return outputs

    def start(self):
        self.go("start")

    def stop(self):
        self.go("stop")

    def shuttingDown(self) -> bool:
        return self.go("shuttingDown")

    def waitForShutdown(self):
        self.go("waitForShutdown")

    def synchronizingToNetwork(self) -> bool:
        return self.go("synchronizingToNetwork")

    def chainSynced(self) -> bool:
        return self.go("chainSynced")

    def setChainSynced(self, synced: bool):
        self.go("setChainSynced", synced)

    def createSimpleTx(
        self,
        acct: int,
        outputs: List[msgtx.TxOut],
        minConf: int,
        satPerKb: float,
        dryRun: bool,
    ) -> AuthoredTx:
        res = self.go("createSimpleTx", dict(
            account=acct,
            outputs=[dict(script=to.pkScript.hex(), value=to.value) for to in outputs],
            minconf=minConf,
            satPerKb=satPerKb,
            dryRun=dryRun,
        ))

        return AuthoredTx(
            tx=msgtx.MsgTx.deserialize(ByteArray(res["tx"])),
            prevScripts=[ByteArray(s) for s in res["prevScripts"]],
            prevInputValues=res["prevInputValues"],
            totalInput=res["totalInput"],
            changeIndex=res["changeIndex"],
        )

    def unlock(self, passphrase: str, timeout: int):
        self.go("unlock", dict(passphrase=ByteArray(passphrase.encode("utf-8")).hex(), timeout=timeout))

    def lock(self):
        self.go("lock")

    def locked(self) -> bool:
        return self.go("locked")

    def changePrivatePassphrase(self, old: str, new: str):
        self.go("changePrivatePassphrase", dict(
            old=ByteArray(old.encode("utf-8")).hex(),
            new=ByteArray(new.encode("utf-8")).hex(),
        ))

    def changePublicPassphrase(self, old: str, new: str):
        self.go("changePublicPassphrase", dict(
            old=ByteArray(old.encode("utf-8")).hex(),
            new=ByteArray(new.encode("utf-8")).hex(),
        ))

    def changePassphrases(self, publicOld: str, publicNew: str, privateOld: str, privateNew: str):
        self.go("changePassphrases", dict(
            public=dict(
                old=ByteArray(publicOld.encode("utf-8")).hex(),
                new=ByteArray(publicNew.encode("utf-8")).hex(),
            ),
            private=dict(
                old=ByteArray(privateOld.encode("utf-8")).hex(),
                new=ByteArray(privateNew.encode("utf-8")).hex(),
            ),
        ))

    def accountAddresses(self, acct: int) -> List[addrlib.Address]:
        return [addrlib.decodeAddress(a, self.netParams) for a in self.go("accountAddresses", acct)]

    def calculateBalance(self, confirms: int) -> int:
        # func (w *Wallet) CalculateBalance(confirms int32) (btcutil.Amount, error)
        return self.go("calculateBalance", confirms)

    def calculateAccountBalances(self, acct: int, confirms: int) -> Balances:
        res = self.go("calculateAccountBalances", dict(
            account=acct,
            confirms=confirms,
        ))

        return Balances(
            total=res["total"],
            spendable=res["spendable"],
            immatureReward=res["immatureReward"],
        )

    def currentAddress(self, acct: int, scope: Union[KeyScope, None] = None) -> addrlib.Address:
        return addrlib.decodeAddress(self.go("currentAddress", dict(
            account=acct,
            scope=parseScope(scope),
        )), self.netParams)

    def pubKeyForAddress(self, addr: addrlib.Address) -> PublicKey:
        pkb = ByteArray(self.go("pubKeyForAddress", addr.string()))
        return Curve.parsePubKey(pkb)

    def privKeyForAddress(self, addr: addrlib.Address) -> PrivateKey:
        return PrivateKey.fromBytes(ByteArray(self.go("privKeyForAddress", addr.string())))

    def labelTransaction(self, h: ByteArray, label: str, overwrite: bool):
        self.go("labelTransaction", dict(
            hash=h.hex(),
            label=label,
            overwrite=overwrite,
        ))

    def haveAddress(self, addr: addrlib.Address) -> bool:
        return self.go("haveAddress", addr.string())

    def accountOfAddress(self, addr: addrlib.Address) -> int:
        return self.go("accountOfAddress", addr.string())

    def addressInfo(self, addr: addrlib.Address) -> ManagedAddress:
        res = self.go("addressInfo", addr.string())

        return ManagedAddress(
            acct=res["account"],
            addr=addrlib.decodeAddress(res["address"], self.netParams),
            addrHash=ByteArray(res["addrHash"]),
            imported=res["imported"],
            internal=res["internal"],
            compressed=res["compressed"],
            addrType=res["addrType"],
        )

    def accountNumber(self, accountName: str, scope: Union[KeyScope, None] = None) -> int:
        return self.go("accountNumber", dict(
            accountName=accountName,
            scope=parseScope(scope),
        ))

    def accountName(self, accountNumber: int, scope: Union[KeyScope, None] = None) -> str:
        return self.go("accountName", dict(
            accountNumber=accountNumber,
            scope=parseScope(scope),
        ))

    def accountProperties(self, accountNumber: int, scope: Union[KeyScope, None] = None) -> AccountProperties:
        res = self.go("accountProperties", dict(
            accountNumber=accountNumber,
            scope=parseScope(scope),
        ))

        return AccountProperties(
            accountNumber=res["accountNumber"],
            accountName=res["accountName"],
            externalKeyCount=res["externalKeyCount"],
            internalKeyCount=res["internalKeyCount"],
            importedKeyCount=res["importedKeyCount"],
        )

    def renameAccount(self, accountNumber: int, newName: str, scope: Union[KeyScope, None] = None):
        self.go("renameAccount", dict(
            accountNumber=accountNumber,
            newName=newName,
            scope=scope.dict(),
        ))

    def nextAccount(self, accountName: str, scope: Union[KeyScope, None] = None) -> int:
        return self.go("nextAccount", dict(
            accountName=accountName,
            scope=parseScope(scope),
        ))

    def requestListTransactions(self, func: str, params: JSONType) -> List[ListTransactionsResult]:
        results = []

        for row in self.go(func, params):

            results.append(ListTransactionsResult(
                abandoned=row["abandoned"],
                account=row["account"],
                amount=row["amount"],
                category=row["category"],
                confirmations=row["confirmations"],
                time=row["time"],
                timeReceived=row["timereceived"],
                trusted=row["trusted"],
                txid=row["txid"],
                vout=row["vout"],
                address=row.get("address"),
                bip125=row.get("bip125"),
                blockHash=row.get("blockhash"),
                blockHeight=row.get("blockheight"),
                blockIndex=row.get("blockindex"),
                blockTime=row.get("blocktime"),
                fee=row.get("fee"),
                generated=row.get("generated"),
                involvesWatchOnly=row.get("involveswatchonly"),
                label=row.get("label"),
                walletConflicts=row.get("walletconflicts"),
                comment=row.get("comment"),
                otherAccount=row.get("otheraccount"),
            ))

        return results

    def listSinceBlock(self, start: int, end: int, syncHeight: int) -> List[ListTransactionsResult]:
        return self.requestListTransactions("listSinceBlock", dict(
            start=start,
            end=end,
            syncHeight=syncHeight,
        ))

    def listTransactions(self, skip: int, count: int) -> List[ListTransactionsResult]:
        return self.requestListTransactions("listTransactions", {
            "from": skip,  # from is a Python keyword
            "count": count,
        })

    def listAddressTransactions(self, addrs: List[str]) -> List[ListTransactionsResult]:
        return self.requestListTransactions("listAddressTransactions", addrs)

    def listAllTransactions(self) -> List[ListTransactionsResult]:
        return self.requestListTransactions("listAllTransactions", "")

    def accounts(self, scope: Union[KeyScope, None] = None) -> AccountsResult:
        res = self.go("accounts", dict(
            coin=scope.coin,
            purpose=scope.purpose if scope else KeyScopeBIP0044,
        ))

        accounts = [AccountResult(
            totalBalance=acct["totalBalance"],
            accountNumber=acct["accountNumber"],
            accountName=acct["accountName"],
            externalKeyCount=acct["externalKeyCount"],
            internalKeyCount=acct["internalKeyCount"],
            importedKeyCount=acct["importedKeyCount"],
        ) for acct in res["accounts"]]

        return AccountsResult(
            accounts=accounts,
            currentBlockHash=ByteArray(res["currentBlockHash"]),
            currentBlockHeight=res["currentBlockHeight"],
        )

    def accountBalances(self, requiredConfs: int, scope: Union[KeyScope, None] = None) -> List[AccountBalanceResult]:
        rows = self.go("accountBalances", dict(
            requiredConfs=requiredConfs,
            scope=parseScope(scope),
        ))

        return [AccountBalanceResult(
            accountNumber=row["accountNumber"],
            accountName=row["accountName"],
            accountBalance=row["accountBalance"],
        ) for row in rows]

    def listUnspent(self, minConf: int, maxConf: int, addresses: List[str]) -> List[ListUnspentResult]:
        rows = self.go("listUnspent", dict(
            minConf=minConf,
            maxConf=maxConf,
            addresses=addresses,
        ))

        results = []

        for row in rows:
            redeemScript = row.get("redeemScript")
            if redeemScript:
                redeemScript = ByteArray(redeemScript)
            results.append(ListUnspentResult(
                    txid=row["txid"],
                    vout=row["vout"],
                    address=row["address"],
                    account=row["account"],
                    scriptPubKey=ByteArray(row["scriptPubKey"]),
                    amount=row["amount"],
                    confirmations=row["confirmations"],
                    spendable=row["spendable"],
                    redeemScript=redeemScript,
            ))

        return results

    def dumpPrivKeys(self) -> List[PrivateKey]:
        return [PrivateKey.fromBytes(ByteArray(s))for s in self.go("dumpPrivKeys")]

    def dumpWIFPrivateKey(self, addr: addrlib.Address) -> addrlib.WIF:
        return addrlib.WIF.decode(self.go("dumpWIFPrivateKey", addr.string()))

    def importPrivateKey(self, wif: addrlib.WIF, bs: BlockStamp, rescan: bool, scope: Union[KeyScope, None] = None) -> str:
        return self.go("importPrivateKey", dict(
            wif=wif.dict(),
            blockStamp=bs.dict(),
            rescan=rescan,
            keyScope=parseScope(scope),
        ))

    def lockedOutpoint(self, op: msgtx.OutPoint) -> bool:
        return self.go("lockedOutpoint", op.dict())

    def unlockOutpoint(self, op: msgtx.OutPoint):
        return self.go("unlockOutpoint", op.dict())

    def lockOutpoint(self, op: msgtx.OutPoint):
        return self.go("lockOutpoint", op.dict())

    def resetLockedOutpoints(self):
        return self.go("resetLockedOutpoints")

    def lockedOutpoints(self) -> List[msgtx.OutPoint]:
        rows = self.go("lockedOutpoints")
        return [msgtx.OutPoint(
            txHash=reversed(ByteArray(row["txid"])),
            idx=row["vout"]
        ) for row in rows]

    def leaseOutput(self, lockID: ByteArray, op: msgtx.OutPoint) -> int:
        return self.go("leaseOutput", dict(
            id=lockID.hex(),
            op=op.dict(),
        ))

    def releaseOutput(self, lockID: ByteArray,  op: msgtx.OutPoint):
        return self.go("releaseOutput", dict(
            id=lockID.hex(),
            op=op.dict(),
        ))

    def sortedActivePaymentAddresses(self) -> List[str]:
        return self.go("sortedActivePaymentAddresses")

    def _newAddressFunc(self, func: str, acct: int, scope: Union[KeyScope, None] = None) -> addrlib.Address:
        a = self.go(func, dict(
            account=acct,
            scope=parseScope(scope),
        ))
        return addrlib.decodeAddress(a, self.netParams)

    def newAddress(self, acct: int, scope: Union[KeyScope, None] = None) -> addrlib.Address:
        return self._newAddressFunc("newAddress", acct, scope)

    def newChangeAddress(self, acct: int, scope: Union[KeyScope, None] = None) -> addrlib.Address:
        return self._newAddressFunc("newChangeAddress", acct, scope)

    def totalReceivedForAccounts(self, minConf: int, scope: Union[KeyScope, None] = None) -> List[AccountTotalReceivedResult]:
        rows = self.go("totalReceivedForAccounts", dict(
            minConf=minConf,
            scope=parseScope(scope),
        ))
        return [AccountTotalReceivedResult(
            accountNumber=row["accountNumber"],
            accountName=row["accountName"],
            totalReceived=row["totalReceived"],
            lastConfirmation=row["lastConfirmation"],
        ) for row in rows]

    def totalReceivedForAddr(self, addr: addrlib.Address, minConf: int) -> int:
        return self.go("totalReceivedForAddr", dict(
            addr=addr.string(),
            minConf=minConf,
        ))

    def sendOutputs(self, outputs: List[msgtx.TxOut], acct: int, minConf: int, satPerKb: float, label: str) -> msgtx.MsgTx:
        msgTxB = ByteArray(self.go("sendOutputs", dict(
            outputs=[dict(script=to.pkScript.hex(), value=to.value) for to in outputs],
            account=acct,
            minConf=minConf,
            satPerKb=satPerKb,
            label=label,
        )))
        return msgtx.MsgTx.deserialize(msgTxB)

    def signTransaction(
        self,
        tx: msgtx.MsgTx,
        hashType: int,
        additionalPrevScripts: Dict[str, ByteArray],  # key is outpoint ID txid:index, e.g. a27e1f:1
        additionalKeysByAddress: Dict[str, addrlib.WIF],
        p2shRedeemScriptsByAddress: Dict[str, ByteArray],
    ):
        resp = self.go("signTransaction", dict(
            tx=tx.serialize().hex(),
            hashType=hashType,
            additionalPrevScripts={k: v.hex() for k, v in additionalPrevScripts.items()},
            additionalKeysByAddress={k: v.dict() for k, v in additionalKeysByAddress.items()},
            p2shRedeemScriptsByAddress={k: v.hex() for k, v in p2shRedeemScriptsByAddress.items()},
        ))

        sigErrs = resp["sigErrs"]
        if sigErrs:
            raise DecredError(f"signature errors: {sigErrs}")

        signedTx = msgtx.MsgTx.deserialize(ByteArray(resp["signedTx"]))
        tx.txIn = signedTx.txIn  # "sign" the input transaction

    def publishTransaction(self, tx: msgtx.MsgTx, label: str):
        self.go("publishTransaction", dict(
            tx=tx.serialize().hex(),
            label=label,
        ))

    def syncStatus(self) -> SyncStatus:
        res = self.go("syncStatus")
        return SyncStatus(target=res["target"], height=res["height"], syncing=res["syncing"])


# TODO
# func (w *Wallet) SubmitRescan(job *RescanJob) <-chan error

# TODO
# func (w *Wallet) Rescan(addrs []btcutil.Address, unspent []wtxmgr.Credit) error

# TODO
# func (w *Wallet) GetTransactions(startBlock, endBlock *BlockIdentifier, cancel <-chan struct{}) (*GetTransactionsResult, error)

# TODO: Just pass the name and grab the python versions Python-side.
# func (w *Wallet) ChainParams() *chaincfg.Params

# INTERNAL USE ONLY
# func (w *Wallet) SynchronizeRPC(chainClient chain.Interface)

# INTERNAL USE ONLY
# func (w *Wallet) ChainClient() chain.Interface

# We can also get direct access to these methods in SPV mode.
#
# Neutrino ChainService methods
# =============================
# BestBlock() (*headerfs.BlockStamp, error)
# GetBlockHash(height int64) (*chainhash.Hash, error)
# GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error)
# GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error)
# GetBlockHeight(hash *chainhash.Hash) (int32, error)
# BanPeer(addr string, reason banman.Reason) error
# IsBanned(addr string) bool
# AddPeer(sp *ServerPeer)
# AddBytesSent(bytesSent uint64)
# AddBytesReceived(bytesReceived uint64)
# NetTotals() (uint64, uint64)
# SendTransaction(tx *wire.MsgTx) error
# UpdatePeerHeights(latestBlkHash *chainhash.Hash, latestHeight int32, updateSource *ServerPeer)
# ChainParams() chaincfg.Params
# Start() error
# Stop() error
# IsCurrent() bool
# PeerByAddr(addr string) *ServerPeer
# ConnectedCount() int32
# ConnectedPeers() (<-chan query.Peer, func(), error)
# OutboundGroupCount(key string) int
# AddedNodeInfo() []*ServerPeer
# Peers() []*ServerPeer
# DisconnectNodeByAddr(addr string) error
# DisconnectNodeByID(id int32) error
# RemoveNodeByAddr(addr string) error
# RemoveNodeByID(id int32) error
# ConnectNode(addr string, permanent bool) error
# ForAllPeers(closure func(sp *ServerPeer))
# GetCFilter(blockHash chainhash.Hash, filterType wire.FilterType, options ...QueryOption) (*gcs.Filter, error)
# GetBlock(blockHash chainhash.Hash, options ...QueryOption) (*btcutil.Block, error)
# GetUtxo(options ...RescanOption) (*SpendReport, error)
