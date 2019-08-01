"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

pyDcrDdta
DcrdataClient.endpointList() for available enpoints.
"""
import urllib.request as urlrequest
from urllib.parse import urlparse, urlencode

import time
import calendar
import unittest
import threading
import ssl
import sys
import select
import atexit
import os
import websocket
from tempfile import TemporaryDirectory
from tinydecred.util import tinyjson, helpers, database
from tinydecred.crypto import opcode, crypto
from tinydecred.crypto.bytearray import ByteArray
from tinydecred.api import InsufficientFundsError
from tinydecred.pydecred import txscript, simnet
from tinydecred.pydecred.wire import msgtx, wire, msgblock
from tinydecred.util.database import KeyValueDatabase

log = helpers.getLogger("DCRDATA") # , logLvl=0)

VERSION = "0.0.1"
HEADERS = {"User-Agent": "PyDcrData/%s" % VERSION}

# Many of these constants were pulled from the dcrd, and are left as mixed case
# to maintain reference. 

# DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
DefaultRelayFeePerKb = 1e4

# AtomsPerCent is the number of atomic units in one coin cent.
AtomsPerCent = 1e6

# AtomsPerCoin is the number of atomic units in one coin.
AtomsPerCoin = 1e8

# MaxAmount is the maximum transaction amount allowed in atoms.
# Decred - Changeme for release
MaxAmount = 21e6 * AtomsPerCoin

opNonstake = opcode.OP_NOP10

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

# P2PKHPkScriptSize is the size of a transaction output script that
# pays to a compressed pubkey hash.  It is calculated as:

#   - OP_DUP
#   - OP_HASH160
#   - OP_DATA_20
#   - 20 bytes pubkey hash
#   - OP_EQUALVERIFY
#   - OP_CHECKSIG
P2PKHPkScriptSize = 1 + 1 + 1 + 20 + 1 + 1

formatTraceback = helpers.formatTraceback

def getUri(uri):
    return performRequest(uri)

def postData(uri, data):
    return performRequest(uri, data)

def performRequest(uri, post=None):
    try:
        headers = HEADERS
        if post:
            encoded = tinyjson.dump(post).encode("utf-8")
            req = urlrequest.Request(uri, data=encoded)
            req.add_header("User-Agent", "PyDcrData/%s" % VERSION)
            req.add_header("Content-Type", "application/json; charset=utf-8")
        else:
            req = urlrequest.Request(uri, headers=headers, method="GET")
        raw = urlrequest.urlopen(req).read().decode()
        try:
            return tinyjson.load(raw)
        except tinyjson.JSONDecodeError:
            # A couple of paths return simple strings or integers. block/best/hash or block/best/height for instance.
            return raw
        except Exception as e:
            raise DcrDataException("JSONError", "Failed to decode server response from path %s: %s : %s" % (uri, raw, formatTraceback(e)))
    except Exception as e:
        raise DcrDataException("RequestError", "Error encountered in requesting path %s: %s" % (uri, formatTraceback(e)))


class DcrdataPath(object):
    """
    DcrdataPath represents some point along a URL. It may just be a node that
    is not an endpoint, or it may be an enpoint, in which case it's `get`
    method will be a valid api call. If it is a node of a longer URL,
    the following nodes are available as attributes. e.g. if this is node A
    along the URL base/A/B, then node B is available as client.A.B.
    """
    def __init__(self):
        self.subpaths = {}
        self.callSigns = []
    def getSubpath(self, subpathPart):
        if subpathPart in self.subpaths:
            return self.subpaths[subpathPart]
        p = self.subpaths[subpathPart] = DcrdataPath()
        return p
    def addCallsign(self, argList, template):
        """
        Some paths have multiple call signatures or optional parameters.
        Keeps a list of arguments associated with path templates to differentiate.
        """
        self.callSigns.append((argList, template))
    def getCallsignPath(self, *args, **kwargs):
        """
        Find the path template that matches the passed arguments.
        """
        argLen = len(args) if args else len(kwargs)
        for argList, template in self.callSigns:
            if len(argList) != argLen:
                continue
            if args:
                uri = template % args
                if len(kwargs):
                    uri += "?"+urlencode(kwargs)
                return uri
            if all([x in kwargs for x in argList]):
                return template % tuple(kwargs[x] for x in argList)
        raise DcrDataException("ArgumentError", "Supplied arguments, %r, do not match any of the know call signatures, %r." % 
            (args if args else kwargs, [argList for argList, _ in self.callSigns]))
    def __getattr__(self, key):
        if key in self.subpaths:
            return self.subpaths[key]
        raise DcrDataException("SubpathError", "No subpath %s found in datapath" % (key,))

    def __call__(self, *args, **kwargs):
        return getUri(self.getCallsignPath(*args, **kwargs))

    def post(self, data):
        return postData(self.getCallsignPath(), data)

def getSocketURIs(uri):
    uri = urlparse(uri)
    prot = "wss" if uri.scheme == "https" else "ws"
    fmt = "{}://{}/{}"
    ws = fmt.format(prot, uri.netloc, "ws")
    ps = fmt.format(prot, uri.netloc, "ps")
    return ws, ps

class DcrdataClient(object):
    """
    DcrdataClient represents the base node. The only argument to the
    constructor is the path to a DCRData server, e.g. http://explorer.dcrdata.org.
    """
    timeFmt = "%Y-%m-%d %H:%M:%S"

    def __init__(self, baseURI, customPaths=None, emitter=None):
        """
        Build the DcrdataPath tree. 
        """
        self.baseURI = baseURI.rstrip('/').rstrip("/api")
        self.baseApi = self.baseURI + "/api"
        self.wsURI, self.psURI = getSocketURIs(self.baseURI)
        self.ws = None
        self.ps = None
        self.subscribedAddresses = []
        self.emitter = emitter
        atexit.register(self.close)
        root = self.root = DcrdataPath()
        self.listEntries = []
        customPaths = customPaths if customPaths else []
        # /list returns a json list of enpoints with parameters in template format, base/A/{param}/B
        endpoints = getUri(self.baseApi + "/list")
        endpoints += customPaths

        def getParam(part):
            if part.startswith('{') and part.endswith('}'):
                return part[1:-1]
            return None
        pathlog = []
        for path in endpoints:
            path = path.rstrip("/")
            if path in pathlog or path == "":
                continue
            pathlog.append(path)
            baseURI = self.baseURI if "insight" in path else self.baseApi
            params = []
            pathSequence = []
            templateParts = []
            # split the path into an array for nodes and an array for pararmeters
            for i, part in enumerate(path.strip('/').split('/')):
                param = getParam(part)
                if param:
                    params.append(param)
                    templateParts.append("%s")
                else:
                    pathSequence.append(part)
                    templateParts.append(part)
            pathPointer = root
            for pathPart in pathSequence:
                pathPointer = pathPointer.getSubpath(pathPart)
            pathPointer.addCallsign(params, "/".join([baseURI] + templateParts))
            if len(pathSequence) == 1:
                continue
            self.listEntries.append(("%s(%s)" % (".".join(pathSequence), ", ".join(params)), path))

    def __getattr__(self, key):
        return getattr(self.root, key)
    def close(self):
        if self.ws:
            self.ws.close()
        if self.ps:
            self.ps.close()
    def endpointList(self):
        return [entry[1] for entry in self.listEntries]
    def endpointGuide(self):
        """
        Print on endpoint per line. 
        Each line shows a translation from Python notation to a URL.
        """
        print("\n".join(["%s  ->  %s" % entry for entry in self.listEntries]))
    def psClient(self):
        if self.ps is None:
            self.ps = WebsocketClient(self.psURI, emitter=self.emitter, exitObject={"done": "done"})
            self.ps.activate()
        return self.ps

    def subscribeAddresses(self, addrs):
        """
        addrs: list(str) or str
            A base58 encoded address or list of addresses to subscribe to
        """
        if isinstance(addrs, str):
            addrs = [addrs]
        ps = self.psClient()
        subscribed = self.subscribedAddresses
        for a in addrs:
            if a in subscribed:
                continue
            subscribed.append(a)
            ps.send(Sub.address(a))
    def subscribeBlocks(self):
        ps = self.psClient()
        ps.send(Sub.newblock)
    @staticmethod
    def timeStringToUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, DcrdataClient.timeFmt))
    @staticmethod
    def RFC3339toUnix(fmtStr):
        return calendar.timegm(time.strptime(fmtStr, "%Y-%m-%dT%H:%M:%SZ"))


_subcounter = 0

def makeSubscription(eventID):
    global _subcounter
    _subcounter += 1
    return {
      "event": "subscribe",
      "message": {
        "request_id": _subcounter,
        "message": eventID,
      }
    }

class Sub:
    newblock = makeSubscription("newblock")
    mempool = makeSubscription("mempool")
    ping = makeSubscription("ping")
    newtxs = makeSubscription("newtxs")
    blockchainSync = makeSubscription("blockchainSync")
    def address(addr):
        global _subcounter
        _subcounter += 1
        return {
          "event": "subscribe",
          "message": {
            "request_id": _subcounter,
            "message": "address:%s" % addr,
          }
        }

class WebsocketClient(object):
    """
    A WebSocket client.
    """
    def __init__(self, path, emitter=None, exitObject=None, decoder=None, encoder=None):
        """
        See python `socketserver documentation  <https://docs.python.org/3/library/socketserver.html/>`_. for inherited attributes and methods.
        
        Parameters
        ----------
        path: string
            URI for the websocket connection
        decoder: func(str), default tinyjson.load
            A function for processing the string from the server

        """
        self.path = path
        self.emitter = emitter
        self.exitObject = exitObject
        self.killerBool = False
        self.earThread = None
        self.handlinBidness = False
        self.socket = None
        self.decoder = decoder if decoder else tinyjson.load
        self.encoder = encoder if encoder else tinyjson.dump
    def activate(self):
        """
        Start the server and begin parsing messages
        Returns
        -------
        True on success. On failure, StrataMinerServer::errMsg is set, and False is returned
        """
        self.socket = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
        self.socket.connect(self.path)
        self.earThread = threading.Thread(target=self.listenLoop)
        self.earThread.start()
        if not self.earThread.is_alive():
            self.errMsg = "Failed to create a server thread"
            return False
        self.errMsg = ""
        return True
    def listenLoop(self):
        """
        This will listen on the socket, with appropriate looping impelemented with select.select
        """
        stringBuffer = ""
        self.handlinBidness = True
        decoder = self.decoder
        while True:
            if self.killerBool:
                break
            while True:
                if self.killerBool:
                    break
                try:
                    status = select.select([self.socket], [], [], 1)
                    sys.stdout.flush()
                except OSError as e:
                    if(e.errno == 9):
                        #OSError: [Errno 9] Bad file descriptor
                        pass # probably client closed socket
                    break
                if status[0]:
                    try:
                        stringBuffer += self.socket.recv()
                    except ConnectionResetError:
                        break  # ConnectionResetError: [Errno 104] Connection reset by peer
                    except UnicodeDecodeError as e:
                        log.error("Error decoding message from client. Msg: '%s', Error:  %s" % (stringBuffer, formatTraceback(e)))
                        continue
                    except websocket._exceptions.WebSocketConnectionClosedException:
                        # Connection has been closed
                        break
                    except OSError as e:
                        if(e.errno == 9):
                            #OSError: [Errno 9] Bad file descriptor
                            pass # socket was closed 
                        break
                    if stringBuffer == "": # server probably closed socket
                        break
                    else:
                        try:
                            job = decoder(stringBuffer)
                            self.emitter(job)
                            stringBuffer = ""
                            continue
                        except Exception as e:
                            log.Error("error loading message: %s" % formatTraceback(e))
                            continue
        if self.exitObject:
            self.emitter(self.exitObject)
        self.handlinBidness = False
    def send(self, msg): 
        if not self.socket:
            log.error("no socket")
            return          
        try: 
            self.socket.send(self.encoder(msg))
        except Exception as e:
            log.error("Error while sending websocket message: %s" % formatTraceback(e))
    def close(self):
        """
        Attempts to shutdown the server gracefully. Equivalent to setting StrataMinerServer::killerBool = True
        """
        self.killerBool = True
        if self.socket:
            self.socket.close()


class DcrDataException(Exception):
    def __init__(self, name, message):
        self.name = name
        self.message = message

class UTXO(object):
    """
    The UTXO is the only class fully implemented by the wallet API. BlockChains
    must know how to create and parse UTXO objects and fill fields as required
    by the Wallet.
    """
    def __init__(self, address, txid, vout, ts=None, scriptPubKey=None, 
                 height=-1, amount=0, satoshis=0, maturity=None):
        self.address = address
        self.txid = txid
        self.vout = vout
        self.ts = ts
        self.scriptPubKey = scriptPubKey
        self.height = height
        self.amount = amount
        self.satoshis = satoshis
        self.maturity = maturity
    def __tojson__(self):
        return {
            "address": self.address,
            "txid": self.txid,
            "vout": self.vout,
            "ts": self.ts,
            "scriptPubKey": self.scriptPubKey,
            "height": self.height,
            "amount": self.amount,
            "satoshis": self.satoshis,
            "maturity": self.maturity,
        }
    @staticmethod
    def __fromjson__(obj):
        return UTXO.parse(obj)
    @staticmethod
    def parse(obj):
        return UTXO(
            address = obj["address"],
            txid = obj["txid"],
            vout = obj["vout"],
            ts = obj["ts"] if "ts" in obj else None,
            scriptPubKey = obj["scriptPubKey"] if "scriptPubKey" in obj else None,
            height = obj["height"] if "height" in obj else -1,
            amount = obj["amount"] if "amount" in obj else 0,
            satoshis = obj["satoshis"] if "satoshis" in obj else 0,
            maturity = obj["maturity"] if "maturity" in obj else None,
        )
    def confirm(self, block, tx, params):
        self.height = block.height
        self.maturity = block.height + params.CoinbaseMaturity if tx.looksLikeCoinbase() else None
        self.ts = block.timestamp
    def isSpendable(self, tipHeight):
        if self.maturity:
            return self.maturity <= tipHeight
        return True
    def key(self):
        return UTXO.makeKey(self.txid, self.vout)
    @staticmethod
    def makeKey(txid, vout):
        return txid + "#" + str(vout)
tinyjson.register(UTXO)


def makeOutputs(pairs, chain): #pairs map[string]dcrutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
    """
    makeOutputs creates a slice of transaction outputs from a pair of address
    strings to amounts.  This is used to create the outputs to include in newly
    created transactions from a JSON object describing the output destinations
    and amounts.

    Args:
        pairs (tuple(str, int)): Base58-encoded address strings and atoms to
            send to the address.
        chain obj: Network parameters.

    Returns:
        list(msgtx.TxOut): Transaction outputs.
    """
    outputs = []
    for addrStr, amt in pairs:
        if amt < 0:
            raise Exception("amt < 0")
        # Make sure its atoms
        if not isinstance(amt, int):
            raise Exception("amt is not integral")
        pkScript = txscript.makePayToAddrScript(addrStr, chain)
        outputs.append(msgtx.TxOut(value=amt, pkScript=pkScript))
    return outputs

def checkOutput(output, fee):
    """
    checkOutput performs simple consensus and policy tests on a transaction
    output.  Returns with errors.Invalid if output violates consensus rules, and
    errors.Policy if the output violates a non-consensus policy.

    Args:
        output (TxOut): The output to check
        fee (float): The transaction fee rate (/kB).

    Returns:
        There is not return value. If an output is deemed invalid, an exception 
        is raised. 
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

def hashFromHex(s):
    """
    Parse a transaction hash or block hash from a hexadecimal string.
    
    Args:
        s (str): A byte-revesed, hexadecimal string encoded hash.

    Returns:
        ByteArray: Decoded hash
    """
    return reversed(ByteArray(s))

def hexFromHash(h):
    """
    Parse a tx or block hash from a ByteArray.

    Args:
        h (ByteArray): A hash of the block or transaction.
    """
    return reversed(h).hex()

def getP2PKHOpCode(pkScript):
    """
    getP2PKHOpCode returns opNonstake for non-stake transactions, or
    the stake op code tag for stake transactions.

    Args:
        pkScript (ByteArray): The pubkey script.

    Returns:
        int: The opcode tag for the script types parsed from the script.
    """
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

def spendScriptSize(pkScript):
    # Unspent credits are currently expected to be either P2PKH or
    # P2PK, P2PKH/P2SH nested in a revocation/stakechange/vote output.
    scriptClass = txscript.getScriptClass(txscript.DefaultScriptVersion, pkScript)

    if scriptClass == txscript.PubKeyHashTy:
        return RedeemP2PKHSigScriptSize
    raise Exception("unimplemented")

def estimateInputSize(scriptSize):
    """
    estimateInputSize returns the worst case serialize size estimate for a tx input
      - 32 bytes previous tx
      - 4 bytes output index
      - 1 byte tree
      - 8 bytes amount
      - 4 bytes block height
      - 4 bytes block index
      - the compact int representation of the script size
      - the supplied script size
      - 4 bytes sequence

    Args: 
        scriptSize int: Byte-length of the script.

    Returns:
        int: Estimated size of the byte-encoded transaction input. 
    """
    return 32 + 4 + 1 + 8 + 4 + 4 + wire.varIntSerializeSize(scriptSize) + scriptSize + 4

def estimateOutputSize(scriptSize):
    """
    estimateOutputSize returns the worst case serialize size estimate for a tx output
      - 8 bytes amount
      - 2 bytes version
      - the compact int representation of the script size
      - the supplied script size

    Args: 
        scriptSize int: Byte-length of the script.

    Returns:
        int: Estimated size of the byte-encoded transaction output. 
    """
    return 8 + 2 + wire.varIntSerializeSize(scriptSize) + scriptSize

def sumOutputSerializeSizes(outputs): # outputs []*wire.TxOut) (serializeSize int) {
    """
    sumOutputSerializeSizes sums up the serialized size of the supplied outputs.

    Args: 
        outputs list(TxOut): Transaction outputs.

    Returns: 
        int: Estimated size of the byte-encoded transaction outputs. 
    """
    serializeSize = 0
    for txOut in outputs:
        serializeSize += txOut.serializeSize()
    return serializeSize

def estimateSerializeSize(scriptSizes, txOuts, changeScriptSize):
    """
    estimateSerializeSize returns a worst case serialize size estimate for a
    signed transaction that spends a number of outputs and contains each
    transaction output from txOuts. The estimated size is incremented for an
    additional change output if changeScriptSize is greater than 0. Passing 0
    does not add a change output.

    Args: 
        scriptSizes list(int): Pubkey script sizes
        txOuts list(TxOut): Transaction outputs.
        changeScriptSize int: Size of the change script.

    Returns: 
        int: Estimated size of the byte-encoded transaction outputs. 
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

def calcMinRequiredTxRelayFee(relayFeePerKb, txSerializeSize):
    """
    calcMinRequiredTxRelayFee returns the minimum transaction fee required for a
    transaction with the passed serialized size to be accepted into the memory
    pool and relayed.

    Args:
        relayFeePerKb (float): The fee per kilobyte.
        txSerializeSize int: (Size) of the byte-encoded transaction.

    Returns:
        int: Fee in atoms.
    """
    # Calculate the minimum fee for a transaction to be allowed into the
    # mempool and relayed by scaling the base fee (which is the minimum
    # free transaction relay fee).  minTxRelayFee is in Atom/KB, so
    # multiply by serializedSize (which is in bytes) and divide by 1000 to
    # get minimum Atoms.
    fee = relayFeePerKb * txSerializeSize / 1000

    if fee == 0 and relayFeePerKb > 0:
        fee = relayFeePerKb

    if fee < 0 or fee > MaxAmount: # dcrutil.MaxAmount:
        fee = MaxAmount
    return round(fee)


def isDustAmount(amount, scriptSize, relayFeePerKb): #amount dcrutil.Amount, scriptSize int, relayFeePerKb dcrutil.Amount) bool {
    """
    isDustAmount determines whether a transaction output value and script length would
    cause the output to be considered dust.  Transactions with dust outputs are
    not standard and are rejected by mempools with default policies.

    Args:
        amount (int): Atoms.
        scriptSize (int): Byte-size of the script.
        relayFeePerKb (float): Fees paid per kilobyte.

    Returns:
        bool: True if the amount is considered dust.
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

class DcrdataBlockchain(object):
    """
    DcrdataBlockchain implements the Blockchain API from tinydecred.api.
    """
    def __init__(self, dbPath, params, datapath, skipConnect=False):
        """
        Args:
            dbPath str: A database file path
            params obj: Network parameters
            datapath str: A uri for a dcrdata server
            skipConnect bool: Skip initial connection
        """
        self.db = KeyValueDatabase(dbPath)
        self.params = params
        # The blockReceiver and addressReceiver will be set when the respective 
        # subscribe* method is called.
        self.blockReceiver = None
        self.addressReceiver = None
        self.datapath = datapath
        self.dcrdata = None
        self.txDB = self.db.getBucket("tx")
        self.heightMap = self.db.getBucket("height", datatypes=("INTEGER", "BLOB"))
        self.headerDB = self.db.getBucket("header")
        self.txBlockMap = self.db.getBucket("blocklink")
        self.tip = None
        if not skipConnect:
            self.connect()

    def connect(self):
        """
        Connect to dcrdata.
        """
        self.dcrdata = DcrdataClient(
            self.datapath, 
            customPaths=(
                "/tx/send",
                "/insight/api/addr/{address}/utxo",
                "insight/api/tx/send"
            ),
            emitter=self.pubsubSignal,
        )
        self.updateTip()
    def close(self):
        """
        close any underlying connections.
        """
        if self.dcrdata:
            self.dcrdata.close()
    def subscribeBlocks(self, receiver):
        """
        Subscribe to new block notifications.

        Args:
            receiver (func(obj)): A function or method that accepts the block 
                notifications.
        """
        self.blockReceiver = receiver
        self.dcrdata.subscribeBlocks()
    def subscribeAddresses(self, addrs, receiver=None):
        """
        Subscribe to notifications for the provided addresses.

        Args:
            addrs (list(str)): List of base-58 encoded addresses.
            receiver (func(obj)): A function or method that accepts the address 
                notifications.
        """
        log.debug("subscribing to addresses %s" % repr(addrs))
        if receiver:
            self.addressReceiver = receiver
        elif self.addressReceiver == None:
            raise Exception("must set receiver to subscribe to addresses")
        self.dcrdata.subscribeAddresses(addrs)
    def processNewUTXO(self, utxo):
        """
        Processes an as-received blockchain utxo. 
        Check for coinbase or stakebase, and assign a maturity as necessary.
        
        Args:
            utxo UTXO: A new unspent transaction output from blockchain. 

        Returns:
            bool: True if no errors are encountered.
        """
        utxo = UTXO.parse(utxo)
        tx = self.tx(utxo.txid)
        if tx.looksLikeCoinbase():
            # This is a coinbase or stakebase transaction. Set the maturity.
            utxo.maturity = utxo.height + self.params.CoinbaseMaturity
        return utxo
    def UTXOs(self, addrs):
        """
        UTXOs will produce any known UTXOs for the list of addresses. 

        Args:
            addrs (list(str)): List of base-58 encoded addresses.
        """
        utxos = []
        addrCount = len(addrs)
        addrsPerRequest = 20 # dcrdata allows 25
        get = lambda addrs: self.dcrdata.insight.api.addr.utxo(",".join(addrs))
        for i in range(addrCount//addrsPerRequest+1):
            start = i*addrsPerRequest
            end = start + addrsPerRequest
            if start < addrCount:
                ads = addrs[start:end]
                utxos += [self.processNewUTXO(u) for u in get(ads)]
        return utxos
    def txVout(self, txid, vout):
        """
        Get a UTXO from the outpoint. The UTXO will not have the address set.

        Args:
            txid (str): Hex-encode txid
        """
        tx = self.tx(txid)
        txout = tx.txOut[vout]
        utxo = UTXO(
            address = None,
            txid = txid,
            vout = vout,
            scriptPubKey = txout.pkScript,
            amount = round(txout.value*1e-8),
            satoshis = txout.value,
        )
        self.confirmUTXO(utxo, None, tx)
        return utxo

    def tx(self, txid):
        """
        Get the MsgTx. Retreive it from the blockchain if necessary. 

        Args:
            txid (str): A hex encoded transaction ID to fetch. 

        Returns:
            MsgTx: The transaction.
        """
        hashKey = hashFromHex(txid).bytes()
        with self.txDB as txDB:
            try:
                encoded = ByteArray(txDB[hashKey])
                return msgtx.MsgTx.deserialize(encoded)
            except database.NoValue:
                try:                            
                    # Grab the hex encoded transaction
                    txHex = self.dcrdata.tx.hex(txid)
                    if not txHex:
                        raise Exception("failed to retrieve tx hex from dcrdata")
                    encoded = ByteArray(txHex)
                    txDB[hashKey] = encoded.bytes()
                    return msgtx.MsgTx.deserialize(encoded)
                except:
                    log.warning("unable to retrieve tx data from dcrdata at %s" % self.dcrdata.baseUri)
        raise Exception("failed to reteive transaction")
    def blockForTx(self, txid):
        """
        Get the BlockHeader for the transaction.

        Args:
            txid (str): The transaction ID.
        """
        txHash = hashFromHex(txid).bytes()
        with self.txBlockMap as txblk:
            try:
                # Try to get the blockhash from the database.
                bHash = txblk[txHash]
                return self.blockHeader(hexFromHash(bHash))
            except database.NoValue:
                # If the blockhash is not in the database, get it from dcrdata
                decodedTx = self.dcrdata.tx(txid)
                if ("block" not in decodedTx or 
                   "blockhash" not in decodedTx["block"] or 
                   decodedTx["block"]["blockhash"] == ""):
                    return None
                hexHash = decodedTx["block"]["blockhash"]
                header = self.blockHeader(hexHash)
                txblk[txHash] = header.hash().bytes()
                return header
    def decodedTx(self, txid):
        """
        decodedTx will produce a transaction as a Python dict. 

        Args:
            txid (str): Hex-encoded transaction ID. 

        Returns:
            dict: A Python dict with transaction information.
        """
        return self.dcrdata.tx(txid)
    def blockHeader(self, hexHash):
        """
        blockHeader will produce a blockHeader implements the BlockHeader API.

        Args:
            bHash (str): The block hash of the block header.

        Returns: 
            BlockHeader: An object which implements the BlockHeader API.
        """
        with self.headerDB as headers:
            try:
                serialized = headers[hashFromHex(hexHash).bytes()]
                return msgblock.BlockHeader.deserialize(serialized)
            except database.NoValue:
                try:
                    block = self.dcrdata.block.hash.header.raw(hexHash)
                    blockHeader = msgblock.BlockHeader.deserialize(ByteArray(block["hex"]))
                    self.saveBlockHeader(blockHeader)
                    return blockHeader
                except Exception as e:
                    log.warning("unable to retrieve block header: %s" % formatTraceback(e))
        raise Exception("failed to get block header for block %s" % hexHash)
    def blockHeaderByHeight(self, height):
        """
        Get the block header by height. The blcck header is retreived from the
        blockchain if necessary, in which case it is stored. 

        Args:
            height int: The block height

        Returns:
            BlockHeader: The block header.
        """
        with self.heightMap as heightMap, self.headerDB as headers:
            try:
                hashKey = heightMap[height]
                serialized = headers[hashKey]
                return msgblock.BlockHeader.deserialize(serialized)
            except database.NoValue:
                try:
                    hexBlock = self.blockchain.block.header.raw(idx=height)
                    blockHeader = msgblock.BlockHeader.deserialize(ByteArray(hexBlock))
                    self.saveBlockHeader(blockHeader)
                    return blockHeader
                except:
                    log.warning("unable to retrieve block header")
        raise Exception("failed to get block header at height %i" % height)
    def bestBlock(self):
        """
        bestBlock will produce a decoded block as a Python dict.
        """
        return self.dcrdata.block.best()
    def updateTip(self):
        """
        Update the tip block. If the wallet is subscribed to block updates, 
        this can be used sparingly.
        """
        try:
            self.tip = self.bestBlock()
            return
        except Exception as e:
            log.error("failed to retrieve tip from blockchain: %s" % formatTraceback(e))
        raise Exception("no tip data retrieved")
    def relayFee(self):
        """
        Return the current transaction fee. 

        Returns:
            int: Atoms per kB of encoded transaction.
        """
        return  DefaultRelayFeePerKb
    def saveBlockHeader(self, header):
        """
        Save the block header to the database.

        Args:
            header (BlockHeader): The block header to save.
        """
        bHash = header.hash().bytes()
        with self.heightMap as heightMap, self.headerDB as headers:
            heightMap[header.height] = bHash
            headers[bHash] = header.serialize().bytes()
    def sendToAddress(self, value, address, keysource, utxosource, feeRate=None):
        """
        Send the amount in atoms to the specified address.

        Args:
            value int: The amount to send, in atoms.
            address str: The base-58 encoded address.
            keysource func(str) -> PrivateKey: A function that returns the 
                private key for an address.
            utxosource func(int, func(UTXO) -> bool) -> list(UTXO): A function 
                that takes an amount in atoms, and an optional filtering 
                function. utxosource returns a list of UTXOs that sum to >= the 
                amount. If the filtering function is provided, UTXOs for which 
                the  function return a falsey value will not be included in the
                returned UTXO list.
            MsgTx: The newly created transaction on success, `False` on failure.
        """
        self.updateTip()
        outputs = makeOutputs([(address, value)], self.params)
        return self.sendOutputs(outputs, keysource, utxosource, feeRate)
    def broadcast(self, txHex):
        """
        Broadcast the hex encoded transaction to dcrdata.

        Args:
            txHex (str): Hex-encoded serialized transaction.
        """
        try:
            log.debug("sending %r to dcrdata" % txHex)
            self.dcrdata.insight.api.tx.send.post({
                "rawtx": txHex,
            })
            return True
        except Exception as e:
            log.error("broadcast error: %s" % e)
        return False
    def pubsubSignal(self, sig):
        """
        Process a notifictation from the block explorer.

        Arg:
            sig (obj or string): The block explorer's notification, decoded.
        """
        # log.debug("pubsub signal recieved: %s" % repr(sig))
        if "done" in sig:
            return
        sigType = sig["event"]
        try:
            if sigType == "address":
                msg = sig["message"]
                log.debug("signal received for %s" % msg["address"])
                self.addressReceiver(msg["address"], msg["transaction"])
            elif sigType == "newblock":
                self.tip = sig["message"]["block"]
                self.tipHeight = self.tip["height"]
                self.blockReceiver(sig)
            elif sigType == "subscribeResp":
                # should check for error.
                pass
            else:
                raise Exception("unknown signal")
        except Exception as e:
            log.error("failed to process pubsub message: %s" % formatTraceback(e))
    def changeScript(self, changeAddress):
        """
        Get a pubkey script for a change output.
        """
        return txscript.makePayToAddrScript(changeAddress, self.params)
    def approveUTXO(self, utxo):
        # If the UTXO appears unconfirmed, see if it can be confirmed.
        if utxo.maturity and self.tip["height"] < utxo.maturity:
            return False
        return True
    def confirmUTXO(self, utxo, block=None, tx=None):
        if not tx:
            # No tx found is an issue, so pass the exception.
            tx = self.tx(utxo.txid)
        try:           
            # No block found is not an error. 
            if not block:
                block = self.blockForTx(utxo.txid)
            utxo.confirm(block, tx, self.params)
            return True
        except:
            pass
        return False
    def sendOutputs(self, outputs, keysource, utxosource, feeRate=None): # , minconf=1, randomizeChangeIdx=True):
        """
        Send the `TxOut`s to the address. 

        mostly based on:
          (dcrwallet/wallet/txauthor).NewUnsignedTransaction
          (dcrwallet/wallet).txToOutputsInternal
          (dcrwallet/wallet/txauthor).AddAllInputScripts

        Args:
            outputs (list(TxOut)): The transaction outputs to send.
            keysource func(str) -> PrivateKey: A function that returns the 
                private key for an address.
            utxosource func(int, func(UTXO) -> bool) -> list(UTXO): A function 
                that takes an amount in atoms, and an optional filtering 
                function. utxosource returns a list of UTXOs that sum to >= the 
                amount. If the filtering function is provided, UTXOs for which 
                the  function return a falsey value will not be included in the
                returned UTXO list.

        Returns:
            MsgTx: The sent transaction.
            list(UTXO): The spent UTXOs.
            list(UTXO): Length 1 array containing the new change UTXO. 
        """
        total = 0
        inputs = []
        scripts = []
        scriptSizes = []

        changeAddress = keysource.change()
        changeScript = self.changeScript(changeAddress)
        changeScriptVersion = txscript.DefaultScriptVersion
        changeScriptSize = P2PKHPkScriptSize

        relayFeePerKb = feeRate * 1e3 if feeRate else self.relayFee()
        for txout in outputs:
            checkOutput(txout, relayFeePerKb)

        signedSize = estimateSerializeSize([RedeemP2PKHSigScriptSize], outputs, changeScriptSize)
        targetFee = calcMinRequiredTxRelayFee(relayFeePerKb, signedSize)
        targetAmount = sum(txo.value for txo in outputs)

        while True:
            utxos, enough = utxosource(targetAmount + targetFee, self.approveUTXO)
            if not enough:
                raise InsufficientFundsError("insufficient funds")
            for utxo in utxos:
                tx = self.tx(utxo.txid)
                # header = self.blockHeaderByHeight(utxo["height"])
                txout = tx.txOut[utxo.vout]

                opCodeClass = getP2PKHOpCode(txout.pkScript)
                tree = wire.TxTreeRegular if opCodeClass == opNonstake else wire.TxTreeStake
                op = msgtx.OutPoint(
                    txHash=tx.hash(), 
                    idx=utxo.vout, 
                    tree=tree
                )
                txIn = msgtx.TxIn(previousOutPoint=op, valueIn=txout.value)

                total += txout.value
                inputs.append(txIn)
                scripts.append(txout.pkScript)
                scriptSizes.append(spendScriptSize(txout.pkScript))

            signedSize = estimateSerializeSize(scriptSizes, outputs, changeScriptSize)
            requiredFee = calcMinRequiredTxRelayFee(relayFeePerKb, signedSize)
            remainingAmount = total - targetAmount
            if remainingAmount < requiredFee:
                targetFee = requiredFee
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
            newUTXOs = []
            changeVout = -1
            changeAmount = round(total - targetAmount - requiredFee)
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
                signedSize = estimateSerializeSize(scriptSizes, newTx.txOut, 0)

            # dcrwallet conditionally randomizes the change position here
            if len(newTx.txIn) != len(scripts):
                raise Exception("tx.TxIn and prevPkScripts slices must have equal length")

            # Sign the inputs
            for i, txin in enumerate(newTx.txIn):
                pkScript = scripts[i]
                sigScript = txin.signatureScript
                scriptClass, addrs, numAddrs = txscript.extractPkScriptAddrs(0, pkScript, self.params)
                privKey = keysource.priv(addrs[0].string())
                script = txscript.signTxOutput(privKey, self.params, newTx, i, pkScript, txscript.SigHashAll, sigScript, crypto.STEcdsaSecp256k1)
                txin.signatureScript = script
            self.broadcast(newTx.txHex())
            if change:
                newUTXOs.append(UTXO(
                    address = changeAddress,
                    txid = newTx.txid(),
                    vout = changeVout,
                    ts = time.time(),
                    scriptPubKey = changeScript,
                    amount = changeAmount*1e-8,
                    satoshis = changeAmount,
                ))

            return newTx, utxos, newUTXOs

class TestDcrdata(unittest.TestCase):
    def test_post(self):
        dcrdata = DcrdataClient("http://localhost:7777", customPaths={
            "/tx/send",
            "/insight/api/addr/{address}/utxo",
            "insight/api/tx/send"
        })

        tx = "01000000010f6d7f5d37408065b3646360a4c40d03a6e2cfbeb285cd800e0eba6e324a0d900200000000ffffffff0200e1f5050000000000001976a9149905a4df9d118e0e495d2bb2548f1f72bc1f305888ac1ec12df60600000000001976a91449c533219ff4eb65603ab31d827c9a22b72b429488ac00000000000000000100ac23fc0600000000000000ffffffff6b483045022100b602bfb324a24801d914ec2f6a48ee27d65e2cde3fa1e71877fda23d7bae4a1f02201210c789dc33fe156bd086c3779af1953e937b24b0bba4a8adb9532b4eda53c00121035fc391f92ba86e8d5b893d832ced31e6a9cc7a9c1cddc19a29fa53dc1fa2ff9f"
        r = dcrdata.insight.api.tx.send.post({
            "rawtx": tx,
        })
        print(repr(r))
    def test_get(self):
        dcrdata = DcrdataClient("http://localhost:7777", customPaths={
            "/tx/send",
            "/insight/api/addr/{address}/utxo",
            "insight/api/tx/send"
        })
        # print(dcrdata.endpointGuide())

        tx = dcrdata.tx.hex("796a0288a5560400cce55e87b8ccd95ba256a2c509a08f1be8d3198f873f5a2d")
    def test_websocket(self):
        """
        "newblock":       SigNewBlock,
        "mempool":        SigMempoolUpdate,
        "ping":           SigPingAndUserCount,
        "newtxs":         SigNewTxs,
        "address":        SigAddressTx,
        "blockchainSync": SigSyncStatus,
        """
        client = DcrdataClient("http://localhost:7777")
        def emitter(o):
            print("msg: %s" % repr(o))
        client.subscribeAddresses("SsUYTr1PBd2JMbaUfiRqxUoRcYHj1a1DKY9", emitter=emitter)
        time.sleep(60*1) # 1 minute
    def test_get_block_header(self):
        with TemporaryDirectory() as tempDir:
            db = database.KeyValueDatabase(os.path.join(tempDir, "db.db"))
            blockchain = DcrdataBlockchain(db, simnet, "http://localhost:7777")
            blockchain.connect()
            blockchain.blockHeader("00000e0cae637353e73ad85fc0073ebb7ed00a0668b068b376a6aef2812e1bf3")

