from tinydecred.crypto import crypto, mnemonic, opcode, txscript
from tinydecred.pydecred import helpers, dcrjson as json, database
from tinydecred.tinycrypto import createNewAccountManager
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.wire import msgtx, msgblock
from tinydecred import wire
import os

log = helpers.getLogger("WLLT", logLvl=0)

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

def utxoKey(u):
    return u["txid"] + "#" + str(u["vout"])

def hashFromString(s):
    return reversed(ByteArray(s))


def decodeAddress(addr, chain): #s string, params *chaincfg.Params) (dcrutil.Address, error) {
    """
    decodeAddress decodes the string encoding of an address and returns
    the Address if addr is a valid encoding for a known address type
    """
    addrLen = len(addr)
    if addrLen == 66 or addrLen == 130:
        # Secp256k1 pubkey as a string, handle differently.
        # return newAddressSecpPubKey(ByteArray(addr), chain)
        raise Exception("decode from secp256k1 pubkey string unimplemented")

    decoded, netID = crypto.b58CheckDecode(addr)

    # regular tx nedID is PubKeyHashAddrID
    if netID == chain.PubKeyHashAddrID:
        return netID, decoded #newAddressPubKeyHash(decoded, chain, crypto.STEcdsaSecp256k1)
    else: 
        raise Exception("unsupported address type")
    # switch netID {
    #     case net.PubKeyAddrID:
    #         return NewAddressPubKey(decoded, net)

    #     case net.PubKeyHashAddrID:
    #         return NewAddressPubKeyHash(decoded, net, dcrec.STEcdsaSecp256k1)

    #     case net.PKHEdwardsAddrID:
    #         return NewAddressPubKeyHash(decoded, net, dcrec.STEd25519)

    #     case net.PKHSchnorrAddrID:
    #         return NewAddressPubKeyHash(decoded, net, dcrec.STSchnorrSecp256k1)

    #     case net.ScriptHashAddrID:
    #         return NewAddressScriptHashFromHash(decoded, net)

    #     default:
    #         return nil, ErrUnknownAddressType
    #     }
    # }

def addData(data):
    dataLen = len(data)
    b = ByteArray(b'')

    # When the data consists of a single number that can be represented
    # by one of the "small integer" opcodes, use that opcode instead of
    # a data push opcode followed by the number.
    if dataLen == 0 or (dataLen == 1 and data[0] == 0):
        b += opcode.OP_0
        return b
    elif dataLen == 1 and data[0] <= 16:
        b += opcode.OP_1-1+data[0]
        return b
    elif dataLen == 1 and data[0] == 0x81:
        b += opcode.OP_1NEGATE
        return b

    # Use one of the OP_DATA_# opcodes if the length of the data is small
    # enough so the data push instruction is only a single byte.
    # Otherwise, choose the smallest possible OP_PUSHDATA# opcode that
    # can represent the length of the data.
    if dataLen < opcode.OP_PUSHDATA1:
        b += (opcode.OP_DATA_1-1)+dataLen
    elif dataLen <= 0xff:
        b += opcode.OP_PUSHDATA1
        b += dataLen
    elif dataLen <= 0xffff:
        b += opcode.OP_PUSHDATA2
        b += ByteArray(dataLen).littleEndian()
    else:
        b += opcode.OP_PUSHDATA4
        b += ByteArray(dataLen, length=4).littleEndian()
    # Append the actual data.
    b.script += data
    return b


def payToAddrScript(netID, pkHash, chain): #addr dcrutil.Address) ([]byte, error) {
    """
    payToAddrScript creates a new script to pay a transaction output to a the
    specified address.
    """
    if netID == chain.PubKeyHashAddrID:
        script = ByteArray(b'')
        script += opcode.OP_DUP
        script += opcode.OP_HASH160
        script += addData(pkHash)
        script += opcode.OP_EQUALVERIFY
        script += opcode.OP_CHECKSIG
        return script
    raise Exception("unimplemented signature type")

    # switch addr := addr.(type) {
    # case *dcrutil.AddressPubKeyHash:
    #     if addr == nil {
    #         return nil, scriptError(ErrUnsupportedAddress,
    #             nilAddrErrStr)
    #     }
    #     switch addr.DSA(addr.Net()) {
    #     case dcrec.STEcdsaSecp256k1:
    #         return payToPubKeyHashScript(addr.ScriptAddress())
    #     case dcrec.STEd25519:
    #         return payToPubKeyHashEdwardsScript(addr.ScriptAddress())
    #     case dcrec.STSchnorrSecp256k1:
    #         return payToPubKeyHashSchnorrScript(addr.ScriptAddress())
    #     }

    # case *dcrutil.AddressScriptHash:
    #     if addr == nil {
    #         return nil, scriptError(ErrUnsupportedAddress,
    #             nilAddrErrStr)
    #     }
    #     return payToScriptHashScript(addr.ScriptAddress())

    # case *dcrutil.AddressSecpPubKey:
    #     if addr == nil {
    #         return nil, scriptError(ErrUnsupportedAddress,
    #             nilAddrErrStr)
    #     }
    #     return payToPubKeyScript(addr.ScriptAddress())

    # case *dcrutil.AddressEdwardsPubKey:
    #     if addr == nil {
    #         return nil, scriptError(ErrUnsupportedAddress,
    #             nilAddrErrStr)
    #     }
    #     return payToEdwardsPubKeyScript(addr.ScriptAddress())

    # case *dcrutil.AddressSecSchnorrPubKey:
    #     if addr == nil {
    #         return nil, scriptError(ErrUnsupportedAddress,
    #             nilAddrErrStr)
    #     }
    #     return payToSchnorrPubKeyScript(addr.ScriptAddress())
    # }

    # str := fmt.Sprintf("unable to generate payment script for unsupported "+
    #     "address type %T", addr)
    # return nil, scriptError(ErrUnsupportedAddress, str)

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
        pkScript = makePayToAddrScript(addrStr, chain)        
        outputs.append(msgtx.TxOut(value=amt, pkScript=pkScript))
    return outputs

def makePayToAddrScript(addrStr, chain):
    if amt < 0:
            raise Exception("amt < 0")
        # Make sure its atoms
        if not isinstance(amt, int):
            raise Exception("amt is not integral")
        netID, pkHash = decodeAddress(addrStr, chain)
        return payToAddrScript(netID, pkHash, chain)


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
    for size = scriptSizes {
        txInsSize += estimateInputSize(size)

    inputCount = len(scriptSizes)
    outputCount = len(txOuts)
    changeSize = 0
    if changeScriptSize > 0:
        changeSize = estimateOutputSize(changeScriptSize)
        outputCount++

    # 12 additional bytes are for version, locktime and expiry.
    return 12 + (2 * wire.varIntSerializeSize(inputCount)) +
        wire.varIntSerializeSize(outputCount) +
        txInsSize +
        h.SumOutputSerializeSizes(txOuts) +
        changeSize

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

class Wallet:
    def __init__(self, chain):
        self.path = None
        self.file = None
        self.setChain(chain)
        self.acctManager = None
        self.openAccount = None
        self.fileKey = None
        self.balance = 0
        self.dcrdatas = []
        self.dbManager = None
        self.db = {}
    def setChain(self, chain):
        self.chain = chain
        self.chainName = chain.Name if chain else None
    def __tojson__(self):
        return {
            "file": self.file,
            "accounts": self.acctManager,
            "chainName": self.chainName,
            "balance": self.balance,
        }
    @staticmethod
    def __fromjson__(obj):
        w = Wallet(None)
        w.chainName = obj["chainName"]
        w.file = obj["file"]
        w.acctManager = obj["accounts"]
        w.balance = obj["balance"]
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
        encrypted = crypto.AES.encrypt(self.fileKey.bytes(), json.dump(self))
        helpers.saveFile(self.path, encrypted)
    @staticmethod
    def open(path, password, chain):
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
    def isOpen(self):
        return bool(self.fileKey)
    def close(self):
        self.save()
        self.fileKey = None
        self.openAccount = None
    def changeScript(self): # []byte, uint16, error
        if not self.openAccount:
            raise Exception("no accounts open")
        changeAddress = self.openAccount.getChangeAddress()
        script = makePayToAddrScript(changeAddress, self.chain)
        return script
    def sync(self, dcrdatas, dbManager, report):
        """
        Run in a threaad. Report should be a Qt signal or similar thread-safe function. 
        """
        self.dcrdatas = dcrdatas
        self.dbManager = dbManager
        acctManager = self.acctManager
        account = acctManager.account(0)
        balance = 0
        for utxos in account.utxos().values():
            for utxo in utxos.values():
                balance += utxo["satoshis"]
            report(balance)
        gapPolicy = 5
        for dcrdata in dcrdatas:
            addrIdx = 0
            lastSeen = 0
            dUtxos = dcrdata.insight.api.addr.utxo
            # dTxs = dcrdata.tx.get
            while True:
                addr = account.getNthPaymentAddress(addrIdx)
                print("--checking address: %s" % addr)
                # insight/api/addr/{address}/utxo
                knownUtxos = account.utxos(addr)
                dcrdataUtxos = dUtxos(addr)
                newUtxos = {}
                dupes = {}
                missingUtxos = {}
                startBalance = balance
                for utxo in dcrdataUtxos:
                    utxoAddr = utxo["address"]
                    if utxoAddr != addr:
                        log.error("dcrdata utxo had wrong address %s != %s" % (utxoAddr, addr))
                    # save a little space by deleting unneeded attributes
                    uKey = utxoKey(utxo)
                    if uKey not in knownUtxos:
                        newUtxos[uKey] = utxo
                        balance += utxo["satoshis"]
                    else:
                        dupes[uKey] = utxo
                for uKey, utxo in knownUtxos.items():
                    if uKey not in dupes:
                        # log.error("dcrdata at %s failed to report a known utxo %s" % (dcrdata.baseUri, txid))
                        # the transaction may have been spent by another copy of this wallet
                        missingUtxos[uKey] = utxo
                        knownUtxos.pop(uKey)
                        balance -= utxo["satoshis"]
                for uKey, utxo in missingUtxos.items():
                    pass # should probably perform some checks here
                for uKey, utxo in newUtxos.items():
                    knownUtxos[uKey] = utxo

                if len(knownUtxos):
                    lastSeen = addrIdx
                addrIdx += 1
                if addrIdx - lastSeen > gapPolicy:
                    break
                if balance != startBalance:
                    report(balance)  
        self.balance = balance
    def getUtxos(self, requested):
        matches = []
        acct = self.openAccount
        collected = 0
        pairs = [(u["satoshis"], u) for u in acct.utxoscan()]
        for v, utxo in sorted(pairs, key=lambda p: p[0]):
            matches.append(utxo)
            collected += v
            if collected >= requested:
                break
        return matches, collected >= requested
    def createRawSpend(self, value, address):
        outputs = makeOutputs((address, value), self.chain)
        self.sendOutputs(outputs)
    def sendOutputs(self, outputs, account=0, minconf=1):
        tx  = self.txToOutputs("wallet.SendOutputs", outputs, account, minconf, True)
        txHash = tx.Tx.TxHash()
        return txHash
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
        for dcrdata in self.dcrdatas:
            txBucket = self.txDB()
            hashKey = hashFromString(txid).bytes()
            source = "database"
            try:
                encoded = txBucket[hashKey]
            except database.NoValue:
                try:
                    source = "dcrdata"
                    # Grab the hex encoded transaction
                    txHex = dcrdata.tx.hex(txid)
                    if not txHex:
                        raise Exception("failed to retrieve tx hex from dcrdata")
                    encoded = ByteArray(txHex)
                    txBucket[hashKey] = encoded.bytes()
                except:
                    log.warning("unable to retrieve tx data from dcrdata at %s" % dcrdata.baseUri)
                    continue
            msgTx = msgtx.MsgTx.decode()
            return msgTx
        raise Exception("failed to get transaction from %s" % source)
    def getHeader(self, height):
        for dcrdata in self.dcrdatas:
            heightMap = self.heightMap()
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
    def txToOutputs(self, outputs, account=0, minconf=1, randomizeChangeIdx=True):
        """
        mostly based on:
          (dcrwallet/wallet/txauthor).NewUnsignedTransaction
          (dcrwallet/wallet).txToOutputsInternal
          (dcrwallet/wallet/txauthor).AddAllInputScripts

        """
        currentTotal = 0
        currentInputs = []
        currentScripts = []
        redeemScriptSizes = []

        changeScript = self.changeScript()
        changeScriptVersion = txscript.DefaultScriptVersion
        changeScriptSize = P2PKHPkScriptSize

        relayFeePerKb = self.relayFee()
        for txout in outputs:
            checkOutput(txout, relayFeePerKb)

        maxSignedSize = estimateSerializeSize([RedeemP2PKHSigScriptSize], outputs, changeScriptSize)
        targetFee = feeForSerializeSize(relayFeePerKb, maxSignedSize)

        targetAmount = sum(txo.value for txo in outputs)

        while:
            utxos, enough = self.getUtxos(targetAmount + targetFee)
            if not enough:
                raise InsufficientFundsError("insufficient funds")
            for utxo in utxos:

                txid = utxo["txid"]
                tx = self.getTx(txid)
                # header = self.getHeader(utxo["height"])
                vout = utxo["vout"]
                txout = tx.txOut[vout]
                # using txmined MakeIgnoredInputSource

                txHash = tx.txHash()

                # use this to get opcode
                opCode = getP2PKHOpCode(txout.pkScript)

                tree = wire.TxTreeRegular
                if opCode != opNonstake:
                    tree = wire.TxTreeStake
                op = msgtx.Outpoint(txHash=txHash, idx=vout, tree=tree)

                txIn = msgtx.TxIn(previousOutPoint=op, valueIn=txout.value)

                currentTotal += txout.value
                currentInputs.append(txIn)
                currentScripts.append(txout.pkScript)
                redeemScriptSizes.append(len(txout.pkScript))

            maxSignedSize = estimateSerializeSize(scriptSizes, outputs, changeScriptSize)
            maxRequiredFee = feeForSerializeSize(relayFeePerKb, maxSignedSize)
            remainingAmount = currentTotal - targetAmount
            if remainingAmount < maxRequiredFee:
                targetFee = maxRequiredFee
                continue

            unsignedTransaction = msgTx.MsgTx(
                serType =  wire.TxSerializeFull,
                version =  generatedTxVersion,
                txIn =     currentInputs,
                txOut =    outputs,
                lockTime = 0,
                expiry =   0,
            )

            changeIndex = -1
            changeAmount = currentTotal - targetAmount - maxRequiredFee
            if changeAmount != 0 and not txrules.isDustAmount(changeAmount, changeScriptSize, relayFeePerKb):
                if len(changeScript) > txscript.MaxScriptElementSize:
                    raise Exception("script size exceed maximum bytes pushable to the stack")
                change = msgtx.TxOut(
                    value =    changeAmount,
                    version =  changeScriptVersion,
                    pkScript = changeScript,
                )
                l = len(outputs)
                unsignedTransaction.txOut.append(change)
                changeIndex = l
            else:
                maxSignedSize = estimateSerializeSize(scriptSizes, unsignedTransaction.txOut, 0)
            
            authoredTransaction = {
                "tx":                           unsignedTransaction,
                "prevScripts":                  currentScripts,
                "totalInput":                   currentTotal,
                "changeIndex":                  changeIndex,
                "estimatedSignedSerializeSize": maxSignedSize,
            }

            # dcrwallet conditionally randomizes the change position here

            inputs = unsignedTransaction.TxIn
            chainParams = self.chain

            if len(inputs) != len(currentScripts):
                raise Exception("tx.TxIn and prevPkScripts slices must have equal length")

            for i, txin in enumerate(inputs):
                pkScript = currentScrips[i]
                sigScript = txin.SignatureScript
                script = self.signTxOutput(chainParams, tx, i, pkScript, txscript.SigHashAll, secrets, secrets, sigScript, dcrec.STEcdsaSecp256k1)
                txin.SignatureScript = script

    def signTxOutput(self, tx, idx, pkScript, hashType, kdb, sdb, previousScript, sigType):
        """
        SignTxOutput signs output idx of the given tx to resolve the script given in
        pkScript with a signature type of hashType. Any keys required will be
        looked up by calling getKey() with the string of the given address.
        Any pay-to-script-hash signatures will be similarly looked up by calling
        getScript. If previousScript is provided then the results in previousScript
        will be merged in a type-dependent manner with the newly generated.
        signature script.
                
        NOTE: This function is only valid for version 0 scripts.  Since the function
        does not accept a script version, the results are undefined for other script
        versions.
        """
        sigScript, class, addresses, nrequired, err := sign(chainParams, tx,
            idx, pkScript, hashType, kdb, sdb, sigType)
        if err != nil {
            return nil, err
        }

        isStakeType := class == StakeSubmissionTy ||
            class == StakeSubChangeTy ||
            class == StakeGenTy ||
            class == StakeRevocationTy
        if isStakeType {
            class, err = GetStakeOutSubclass(pkScript)
            if err != nil {
                return nil, fmt.Errorf("unknown stake output subclass encountered")
            }
        }

        if class == ScriptHashTy {
            // TODO keep the sub addressed and pass down to merge.
            realSigScript, _, _, _, err := sign(chainParams, tx, idx,
                sigScript, hashType, kdb, sdb, sigType)
            if err != nil {
                return nil, err
            }

            // Append the p2sh script as the last push in the script.
            builder := NewScriptBuilder()
            builder.AddOps(realSigScript)
            builder.AddData(sigScript)

            sigScript, _ = builder.Script()
            // TODO keep a copy of the script for merging.
        }

        // Merge scripts. with any previous data, if any.
        mergedScript := mergeScripts(chainParams, tx, idx, pkScript, class,
            addresses, nrequired, sigScript, previousScript)
        return mergedScript, nil
    }


signTxOutput





json.register(Wallet)
