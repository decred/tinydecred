from tinydecred.crypto import crypto, mnemonic, opcode, txscript
from tinydecred.pydecred import helpers, dcrjson as json, database
from tinydecred.tinycrypto import createNewAccountManager, UTXO
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.wire import msgtx, msgblock, wire
from threading import Lock as Mutex
import os
import unittest
import traceback
import time

log = helpers.getLogger("WLLT", logLvl=0)

ACCT = 0

ID_TAG = "tinywallet"
VERSION = "0.0.1"

DefaultRelayFeePerKb = 1e4

# AtomsPerCent is the number of atomic units in one coin cent.
AtomsPerCent = 1e6

# AtomsPerCoin is the number of atomic units in one coin.
AtomsPerCoin = 1e8

# MaxAmount is the maximum transaction amount allowed in atoms.
# Decred - Changeme for release
MaxAmount = 21e6 * AtomsPerCoin

opNonstake = opcode.OP_NOP10

# P2PKHPkScriptSize is the size of a transaction output script that
# pays to a compressed pubkey hash.  It is calculated as:

#   - OP_DUP
#   - OP_HASH160
#   - OP_DATA_20
#   - 20 bytes pubkey hash
#   - OP_EQUALVERIFY
#   - OP_CHECKSIG
P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

# RedeemP2PKHSigScriptSize is the worst case (largest) serialize size
# of a transaction input script that redeems a compressed P2PKH output.
# It is calculated as:
#
#   - OP_DATA_73
#   - 72 bytes DER signature + 1 byte sighash
#   - OP_DATA_33
#   - 33 bytes serialized compressed pubkey
RedeemP2PKHSigScriptSize = 1 + 73 + 1 + 33

# generatedTxVersion is the version of the transaction being generated.
# It is defined as a constant here rather than using the wire.TxVersion
# constant since a change in the transaction version will potentially
# require changes to the generated transaction.  Thus, using the wire
# constant for the generated transaction version could allow creation
# of invalid transactions for the updated version.
generatedTxVersion = 1

class InsufficientFundsError(Exception):
    pass

def hashFromString(s):
    return reversed(ByteArray(s))

def makeOutputs(pairs, chain): #pairs map[string]dcrutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
    """
    makeOutputs creates a slice of transaction outputs from a pair of address
    strings to amounts.  This is used to create the outputs to include in newly
    created transactions from a JSON object describing the output destinations
    and amounts.
    """
    outputs = []
    for addrStr, amt in pairs:
        if amt < 0:
            raise Exception("amt < 0")
        # Make sure its atoms
        if not isinstance(amt, int):
            raise Exception("amt is not integral")
        print("--making  pkScript for %s" % repr(addrStr))
        pkScript = txscript.makePayToAddrScript(addrStr, chain)
        outputs.append(msgtx.TxOut(value=amt, pkScript=pkScript))
    return outputs


def checkOutput(output, fee): #output *wire.TxOut, relayFeePerKb dcrutil.Amount) error {
    """
    CheckOutput performs simple consensus and policy tests on a transaction
    output.  Returns with errors.Invalid if output violates consensus rules, and
    errors.Policy if the output violates a non-consensus policy.
    """
    if output.value < 0:
        raise Exception("transaction output amount is negative")
    if output.value > MaxAmount:
        raise Exception("transaction output amount exceeds maximum value")
    if output.value == 0:
        raise Exception("zero-value output")
    # need to implement these
    # if IsDustOutput(output, fee):
    #     raise Exception("policy violation: transaction output is dust")

def getP2PKHOpCode(pkScript):
    """
    getP2PKHOpCode returns opNonstake for non-stake transactions, or
    the stake op code tag for stake transactions.
    """
    # for now, getScriptClass only recognizes p2pkh
    scriptClass = txscript.getScriptClass(txscript.DefaultScriptVersion, pkScript)
    if scriptClass == txscript.NonStandardTy:
        raise Exception("unknown script class")
    if scriptClass == txscript.StakeSubmissionTy:
        return opcode.OP_SSTX
    elif scriptClass == txscript.StakeGenTy:
        return opcode.OP_SSGEN
    elif scriptClass == txscript.StakeRevocationTy:
        return opcode.OP_SSRTX
    elif scriptClass == txscript.StakeSubChangeTy:
        return opcode.OP_SSTXCHANGE
    # this should always be the case for now.
    return opNonstake

def estimateInputSize(scriptSize):
    """
    EstimateInputSize returns the worst case serialize size estimate for a tx input
      - 32 bytes previous tx
      - 4 bytes output index
      - 1 byte tree
      - 8 bytes amount
      - 4 bytes block height
      - 4 bytes block index
      - the compact int representation of the script size
      - the supplied script size
      - 4 bytes sequence
    """
    return 32 + 4 + 1 + 8 + 4 + 4 + wire.varIntSerializeSize(scriptSize) + scriptSize + 4

def estimateOutputSize(scriptSize):
    """
    EstimateOutputSize returns the worst case serialize size estimate for a tx output
      - 8 bytes amount
      - 2 bytes version
      - the compact int representation of the script size
      - the supplied script size
    """
    return 8 + 2 + wire.varIntSerializeSize(scriptSize) + scriptSize

def sumOutputSerializeSizes(outputs): # outputs []*wire.TxOut) (serializeSize int) {
    """
    sumOutputSerializeSizes sums up the serialized size of the supplied outputs.
    """
    serializeSize = 0
    for txOut in outputs:
        serializeSize += txOut.serializeSize()
    return serializeSize

def estimateSerializeSize(scriptSizes, txOuts, changeScriptSize):
    """
    EstimateSerializeSize returns a worst case serialize size estimate for a
    signed transaction that spends a number of outputs and contains each
    transaction output from txOuts. The estimated size is incremented for an
    additional change output if changeScriptSize is greater than 0. Passing 0
    does not add a change output.
    """
    # Generate and sum up the estimated sizes of the inputs.
    txInsSize = 0
    for size in scriptSizes:
        txInsSize += estimateInputSize(size)

    inputCount = len(scriptSizes)
    outputCount = len(txOuts)
    changeSize = 0
    if changeScriptSize > 0:
        changeSize = estimateOutputSize(changeScriptSize)
        outputCount += 1

    # 12 additional bytes are for version, locktime and expiry.
    return (12 + (2 * wire.varIntSerializeSize(inputCount)) +
        wire.varIntSerializeSize(outputCount) +
        txInsSize +
        sumOutputSerializeSizes(txOuts) +
        changeSize)

def feeForSerializeSize(relayFeePerKb, txSerializeSize):
    """
    FeeForSerializeSize calculates the required fee for a transaction of some
    arbitrary size given a mempool's relay fee policy.
    """
    fee = relayFeePerKb * txSerializeSize / 1000

    if fee == 0 and relayFeePerKb > 0:
        fee = relayFeePerKb

    if fee < 0 or fee > MaxAmount: # dcrutil.MaxAmount:
        fee = MaxAmount
    return fee


def isDustAmount(amount, scriptSize, relayFeePerKb): #amount dcrutil.Amount, scriptSize int, relayFeePerKb dcrutil.Amount) bool {
    """
    IsDustAmount determines whether a transaction output value and script length would
    cause the output to be considered dust.  Transactions with dust outputs are
    not standard and are rejected by mempools with default policies.
    """
    # Calculate the total (estimated) cost to the network.  This is
    # calculated using the serialize size of the output plus the serial
    # size of a transaction input which redeems it.  The output is assumed
    # to be compressed P2PKH as this is the most common script type.  Use
    # the average size of a compressed P2PKH redeem input (165) rather than
    # the largest possible (txsizes.RedeemP2PKHInputSize).
    totalSize = 8 + 2 + wire.varIntSerializeSize(scriptSize) + scriptSize + 165

    # Dust is defined as an output value where the total cost to the network
    # (output size + input size) is greater than 1/3 of the relay fee.
    return amount*1000/(3*totalSize) < relayFeePerKb

class Wallet:
    def __init__(self, chain):
        self.path = None
        self.file = None
        self.setChain(chain)
        self.acctManager = None
        self.openAccount = None
        self.fileKey = None
        self.dcrdatas = []
        self.dbManager = None
        self.db = {}
        self.tip = None
        self.users = 0
        self.balanceSignal = lambda b: None
        self.mtx = Mutex()
    def setChain(self, chain):
        self.chain = chain
        self.chainName = chain.Name if chain else None
    def __tojson__(self):
        return {
            "file": self.file,
            "accounts": self.acctManager,
            "chainName": self.chainName,
        }
    @staticmethod
    def __fromjson__(obj):
        w = Wallet(None)
        w.chainName = obj["chainName"]
        w.file = obj["file"]
        w.acctManager = obj["accounts"]
        return w
    @staticmethod
    def create(path, password, chain, userSeed = None):
        if os.path.isfile(path):
            raise FileExistsError("wallet already exists at path %s" % path)
        wallet = Wallet(chain)
        wallet.path = path
        seed = userSeed.bytes() if userSeed else crypto.generateSeed(crypto.KEY_SIZE)
        # Create the keys and coin type account, using the seed, the public password, private password and blockchain params.
        wallet.acctManager = createNewAccountManager(seed, ''.encode(), password.encode("ascii"), chain)
        wallet.file = {
            "tag": ID_TAG,
            "accounts": wallet.acctManager,
            "version": VERSION,
        }
        wallet.fileKey = crypto.hash160(password)
        wallet.openAccount = wallet.acctManager.openAccount(0, chain, password.encode("ascii"))
        wallet.save()

        if userSeed:
            userSeed.zero()
            return wallet
        words = mnemonic.encode(seed)
        return words, wallet
    @staticmethod
    def createFromMnemonic(words, path, password, chain):
        userSeed = mnemonic.decode(words)
        return Wallet.create(path, password, chain, userSeed=userSeed)
    def save(self):
        if not self.fileKey:
            log.error("attempted to save a closed wallet")
            return
        encrypted = crypto.AES.encrypt(self.fileKey.bytes(), json.dump(self))
        helpers.saveFile(self.path, encrypted)
    @staticmethod
    def openFile(path, password, chain):
        """
        open constructs the wallet from the file
        """
        if not os.path.isfile(path):
            raise FileNotFoundError("no wallet found at %s" % path)
        with open(path, 'r') as f:
            encrypted = f.read()
        fileKey = crypto.hash160(password)
        wallet = json.load(crypto.AES.decrypt(fileKey.bytes(), encrypted))
        wallet.setChain(chain)
        if wallet.file["tag"] != ID_TAG:
            raise IOError("unable to open wallet with provided password")
        if wallet.chainName != chain.Name:
            raise Exception("wrong chain")
        wallet.chain = chain
        wallet.path = path
        wallet.fileKey = fileKey
        wallet.openAccount = wallet.acctManager.openAccount(0, chain, password.encode("ascii"))
        wallet.save()
        return wallet
    def open(self, pw):
        """
        pw: ascii bytes user supplied password
        """
        self.fileKey = crypto.hash160(pw)
        self.openAccount = self.acctManager.openAccount(0, self.chain, pw)
        return self
    def lock(self):
        self.mtx.acquire()
    def unlock(self):
        self.mtx.release()
    def __enter__(self):
        # compount assignment is not thread safe, but standard assignment is.
        u = self.users
        self.users = u + 1
        self.lock()
        return self
    def __exit__(self, xType, xVal, xTB):
        u = self.users
        self.users = u - 1
        self.unlock()
        if self.users == 0:
            self.close()
    def isOpen(self):
        return bool(self.fileKey)
    def close(self):
        self.save()
        # self.fileKey = None
        if self.openAccount:
            self.openAccount.close()
            self.openAccount = None
    def account(self, acct):
        aMgr = self.acctManager
        if len(aMgr.accounts) <= acct:
            raise Exception("requested unknown account number %i" % acct)
        return aMgr.account(acct)
    def processNewUTXO(self, utxo):
        """
        Store related transactions.
        Check for immaturity.
        returns True if utxo has confirmations, False if not
        """
        acct = self.account(ACCT)
        if not utxo.isConfirmed():
            acct.addUTXO(utxo)
            return False
        tx, txIsNew = self.getTx(utxo.txid)
        if txIsNew:
            acct.addTx(utxo.address, utxo.txid)
        if tx.looksLikeCoinbase():
            # this is a coinbase transaction. reject it if it 
            # is not old enough
            utxo.maturity = utxo.height + self.chain.CoinbaseMaturity
        return True
    def getNewAddress(self, acct):
        return self.account(acct).getNextPaymentAddress()
    def paymentAddress(self, acct):
        """
        Gets the payment address at the cursor. 
        As of now, this function does not require unlocking the wallet.
        """
        return self.account(acct).paymentAddress()
    def changeScript(self): # []byte, uint16, error
        if not self.openAccount:
            raise Exception("no accounts open")
        changeAddress = self.openAccount.getChangeAddress()
        script = txscript.makePayToAddrScript(changeAddress, self.chain)
        return script, changeAddress
    def balance(self):
        """ Get the balance of the currently selected account """
        return self.account(ACCT).balance
    def getUtxos(self, requested):
        """
        The wallet is assumed to be opened. 
        """
        matches = []
        acct = self.openAccount
        collected = 0
        pairs = [(u.satoshis, u) for u in acct.utxoscan()]
        for v, utxo in sorted(pairs, key=lambda p: p[0]):
            tx, _ = self.getTx(utxo.txid)
            if utxo.maturity and self.tip["height"] < utxo.maturity:
                continue
            matches.append((utxo, tx))
            collected += v
            if collected >= requested:
                break
        return matches, collected >= requested
    def pubsubSignal(self, sig):
        log.debug("pubsub signal recieved: %s" % repr(sig))
        if "done" in sig:
            return
        self.lock()
        sigType = sig["event"]
        try:
            if sigType == "address":
                self.addressSignal(sig)
            elif sigType == "newblock":
                self.blockSignal(sig)
            elif sigType != "subscribeResp":
                raise Exception("unknown signal")
        except Exception as e:
            log.error("failed to process pubsub message: %s\n%s" % (repr(e), traceback.print_tb(e.__traceback__)))
        self.unlock()
    def blockSignal(self, sig):
        block = sig["message"]["block"]
        self.tip = block
        acct = self.account(ACCT)
        for newTx in block["Tx"]:
            txid = newTx["TxID"]
            if acct.caresAboutTxid(txid):
                tx, _ = self.getTx(txid)
                acct.confirmTx(tx, block["height"])
    def addressSignal(self, sig):
        print("--processing address signal 1")
        acct = self.account(ACCT)
        txid = sig["message"]["transaction"]
        tx, _ = self.getTx(txid)
        decodedTx = self.getDecodedTx(txid)
        block = decodedTx["block"] if "block" in decodedTx else {}
        blockHeight = block["blockheight"] if "blockheight" in block else -1
        blockTime = block["blocktime"] if "blocktime" in block else time.time()
        addr = sig["message"]["address"]
        acct.addTx(addr, txid)
        matches = False
        print("--processing address signal 2")
        for txin in tx.txIn:
            op = txin.previousOutPoint
            match = acct.spendTxidVout(op.hashString(), op.index)
            if match:
                matches += 1
        print("--processing address signal 3")
        for vout, txout in enumerate(tx.txOut):
            try:
                # addrs will be Address objects. Converting to string below.
                _, addrs, _ = txscript.extractPkScriptAddrs(0, txout.pkScript, self.chain)
            except Exception:
                log.debug("unsupported script %s" % txout.pkScript.hex())
                continue
            addrs = [a.string() for a in addrs]
            if addr in addrs:
                log.debug("found new utxo")
                acct.addUTXO(UTXO(
                    address = addr,
                    txid = txid,
                    vout = vout,
                    ts = blockTime,
                    scriptPubKey = txout.pkScript,
                    height = blockHeight,
                    amount = round(txout.value*1e-8),
                    satoshis = txout.value,
                    maturity = blockHeight + self.chain.CoinbaseMaturity if tx.looksLikeCoinbase() else None,
                ))
                matches += 1
        print("--processing address signal 4")
        if matches:
            self.balanceSignal(acct.calcBalance(self.tip["height"]))
        print("--done processing address signal 5")
    def sync(self, dcrdatas, dbManager, balanceSignal):
        """
        Run in a QThread. Report should be a Qt signal or similar thread-safe function. 
        """
        self.dcrdatas = dcrdatas
        self.dbManager = dbManager
        self.balanceSignal = balanceSignal
        acctManager = self.acctManager
        acct = acctManager.account(0)
        self.updateTip()
        gapPolicy = 5
        acct.generateGapAddresses(gapPolicy)
        watchAddresses = set()

        balanceSignal(acct.balance)
        for dcrdata in dcrdatas:
            # dTxs = dcrdata.tx.get
            addresses = acct.allAddresses()
            addrCount = len(addresses)
            addrsPerRequest = 20 # dcrdata allows 25
            for i in range(addrCount//addrsPerRequest+1):
                start = i*addrsPerRequest
                end = start + addrsPerRequest
                addrs = addresses[start:end]
                dcrdataUtxos = [UTXO.parse(u) for u in dcrdata.insight.api.addr.utxo(",".join(addrs))]
                newUtxos = {}
                dupes = {}
                missingUtxos = []
                for utxo in dcrdataUtxos:
                    if acct.getUTXO(utxo.txid, utxo.vout):
                        dupes[utxo.key()] = utxo
                    else:
                        print("--found new utxo for %s" % utxo.address)
                        if self.processNewUTXO(utxo):
                            newUtxos[utxo.key()] = utxo
                for utxo in acct.utxoscan():
                    if utxo.key() in dupes:
                        # log.error("dcrdata at %s failed to report a known utxo %s" % (dcrdata.baseUri, txid))
                        # the transaction may have been spent by another copy of this wallet
                        missingUtxos.append(utxo)
                for utxo in missingUtxos.values():
                    # remove the UTXO
                    acct.removeUTXO(utxo)
                for utxo in newUtxos.values():
                    acct.addUTXO(utxo)
        hub = dcrdatas[0]
        hub.emitter = self.pubsubSignal
        hub.subscribeBlocks()
        watchAddresses = acct.addressesOfInterest()
        if watchAddresses:
            hub.subscribeAddresses(watchAddresses)
        balanceSignal(acct.calcBalance(self.tip["height"]))
        return True
    def updateTip(self):
        for dcrdata in self.dcrdatas:
            try:
                self.tip = dcrdata.block.best()
                return
            except Exception as e:
                log.error("failed to retrieve tip from dcrdata at %s: %r" % (dcrdata.baseUri, e))
                continue
        raise Exception("no tip data retrieved")
    def sendToAddress(self, value, address, sender):
        self.updateTip()
        outputs = makeOutputs([(address, value)], self.chain)
        return self.sendOutputs(outputs, sender)        
    def relayFee(self):
        return  DefaultRelayFeePerKb
    def txDB(self):
        return self.dbManager.getBucket("tx")
    def heightMap(self):
        """ A map of height to block hash."""
        return self.dbManager.getBucket("height", datatypes=("INTEGER", "BLOB"))
    def headerDB(self):
        return self.dbManager.getBucket("header")
    def getTx(self, txid):
        """
        return transaction and a bool indicating whether the transaction is new to 
        the database, or had to be imported from dcrdata
        """
        hashKey = hashFromString(txid).bytes()
        with self.txDB() as txBucket:
            try:
                encoded = ByteArray(txBucket[hashKey])
                return msgtx.MsgTx.deserialize(encoded), False
            except database.NoValue:
                for dcrdata in self.dcrdatas:
                    try:                            
                        # Grab the hex encoded transaction
                        txHex = dcrdata.tx.hex(txid)
                        if not txHex:
                            raise Exception("failed to retrieve tx hex from dcrdata")
                        encoded = ByteArray(txHex)
                        txBucket[hashKey] = encoded.bytes()
                        return msgtx.MsgTx.deserialize(encoded), True
                    except:
                        log.warning("unable to retrieve tx data from dcrdata at %s" % dcrdata.baseUri)
                        continue
        raise Exception("failed to get transaction")
    def getDecodedTx(self, txid):
        """
        return transaction and a bool indicating whether the transaction is new or not.
        """
        for dcrdata in self.dcrdatas:
            return dcrdata.tx(txid)
        raise Exception("failed to get decoded transaction")
    def getHeader(self, height):
        for dcrdata in self.dcrdatas:
            with self.heightMap() as heightMap:
                headerBucket = self.headerDB()
                try:
                    hashKey = heightMap[height]
                    blockHash = headerBucket[hashKey]
                    return msgblock.BlockHeader.deserialize(blockHash)
                except database.NoValue:
                    try:
                        hexBlock = dcrdata.block.header.raw(idx=height)
                        blockHash = ByteArray(hexBlock)
                        heightMap[height] = blockHash
                        blockHeader = msgblock.BlockHeader.deserialize(blockHash)
                        hashKey = blockHeader.blockHash()
                        headerBucket[hashKey] = blockHash
                        return blockHeader
                    except:
                        # try the next dcrdata
                        log.warning("unable to retrieve block header from dcrdata at %s" % dcrdata.baseUri)
                        continue
        raise Exception("failed to get block header at height" % height)
    def sendOutputs(self, outputs, sender, minconf=1, randomizeChangeIdx=True):
        """
        mostly based on:
          (dcrwallet/wallet/txauthor).NewUnsignedTransaction
          (dcrwallet/wallet).txToOutputsInternal
          (dcrwallet/wallet/txauthor).AddAllInputScripts

        """
        total = 0
        inputs = []
        scripts = []
        scriptSizes = []

        changeScript, changeAddress = self.changeScript()
        changeScriptVersion = txscript.DefaultScriptVersion
        changeScriptSize = P2PKHPkScriptSize

        relayFeePerKb = self.relayFee()
        for txout in outputs:
            checkOutput(txout, relayFeePerKb)

        maxSignedSize = estimateSerializeSize([RedeemP2PKHSigScriptSize], outputs, changeScriptSize)
        targetFee = feeForSerializeSize(relayFeePerKb, maxSignedSize)

        targetAmount = sum(txo.value for txo in outputs)
        acct = self.openAccount

        while True:
            txSets, enough = self.getUtxos(targetAmount + targetFee)
            if not enough:
                raise InsufficientFundsError("insufficient funds")
            for (utxo, tx) in txSets:
                # header = self.getHeader(utxo["height"])
                txout = tx.txOut[utxo.vout]

                # use this to get opcode
                opCode = getP2PKHOpCode(txout.pkScript)

                tree = wire.TxTreeRegular if opCode != opNonstake else wire.TxTreeStake
                op = msgtx.OutPoint(
                    txHash=tx.txHash(), 
                    idx=utxo.vout, 
                    tree=tree
                )

                txIn = msgtx.TxIn(previousOutPoint=op, valueIn=txout.value)

                total += txout.value
                inputs.append(txIn)
                scripts.append(txout.pkScript)
                scriptSizes.append(len(txout.pkScript))

            maxSignedSize = estimateSerializeSize(scriptSizes, outputs, changeScriptSize)
            maxRequiredFee = feeForSerializeSize(relayFeePerKb, maxSignedSize)
            remainingAmount = total - targetAmount
            if remainingAmount < maxRequiredFee:
                targetFee = maxRequiredFee
                continue

            newTx = msgtx.MsgTx(
                serType =  wire.TxSerializeFull,
                version =  generatedTxVersion,
                txIn =     inputs,
                txOut =    outputs,
                lockTime = 0,
                expiry =   0,
                cachedHash = None,
            )

            change = None
            changeVout = -1
            changeAmount = round(total - targetAmount - maxRequiredFee)
            if changeAmount != 0 and not isDustAmount(changeAmount, changeScriptSize, relayFeePerKb):
                if len(changeScript) > txscript.MaxScriptElementSize:
                    raise Exception("script size exceed maximum bytes pushable to the stack")
                change = msgtx.TxOut(
                    value =    changeAmount,
                    version =  changeScriptVersion,
                    pkScript = changeScript,
                )
                changeVout = len(newTx.txOut)
                newTx.txOut.append(change)
            else:
                maxSignedSize = estimateSerializeSize(scriptSizes, newTx.txOut, 0)

            # dcrwallet conditionally randomizes the change position here
            if len(newTx.txIn) != len(scripts):
                raise Exception("tx.TxIn and prevPkScripts slices must have equal length")

            # Sign the inputs
            for i, txin in enumerate(newTx.txIn):
                pkScript = scripts[i]
                sigScript = txin.signatureScript
                scriptClass, addrs, numAddrs = txscript.extractPkScriptAddrs(0, pkScript, self.chain)
                print("--addrs: %s" % repr(addrs))
                privKey = acct.getPrivKeyForAddress(addrs[0].string())
                #                              privKey, chainParams, tx, idx, pkScript, hashType, previousScript, sigType
                script = txscript.signTxOutput(privKey, self.chain, newTx, i, pkScript, txscript.SigHashAll, sigScript, crypto.STEcdsaSecp256k1)
                txin.signatureScript = script

                print("--sigScript: %s" % script.hex())
                print("--pkScript: %s" % pkScript.hex())

            try:
                sender(newTx.txHex())
                acct.addMempoolTx(tx)
                acct.spendUTXOs([u for u, _ in txSets])
                if change:
                    acct.addUTXO(UTXO(
                        address = changeAddress,
                        txid = newTx.txid(),
                        vout = changeVout,
                        ts = time.time(),
                        scriptPubKey = changeScript,
                        amount = changeAmount*1e-8,
                        satoshis = changeAmount,
                    ))
                self.balanceSignal(acct.calcBalance(self.tip["height"]))
                return newTx
            except Exception as e:
                log.error("failed to send transaction: %s\n%s" % (repr(e), traceback.print_tb(e.__traceback__)))
            return False
            

        return False


json.register(Wallet)


class TestWallet(unittest.TestCase):
    def test_tx_to_outputs(self):
        pass