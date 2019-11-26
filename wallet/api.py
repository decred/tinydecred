"""
Copyright (c) 2019, Brian Stafford
Copyright (c) 2019, the Decred developers
See LICENSE for details

This module defines an API used by the wallet and implemented by each asset and
node type.
"""

class Unimplemented(Exception):
    """
    Unimplemented method.
    """
    pass

class InsufficientFundsError(Exception):
    """
    Available account balance too low for requested funds.
    """
    pass

class UTXO:
    """
    Blockchain-implementing classes must know how to create and handle utxo
    objects.
    """
    def __init__(self, address, txid, vout):
        """
        Args:
            address (str): Base-58 encoded address string.
            txid (str): Transaction ID.
            vout (int): The transaction output index that this UTXO represents.
        """
        self.address = address
        self.txid = txid
        self.vout = vout
    def __tojson__(self):
        """
        UTXO must be json-encodable and registered with the tinyjson module.
        """
        raise Unimplemented("__tojson__ not implemented")
    @staticmethod
    def __fromjson__(obj):
        """
        Decode the UTXO from the json encoding as returned by __tojson__
        """
        raise Unimplemented("__fromjson__ not implemented")
    def isSpendable(self, tipHeight):
        """
        Determine whether this UTXO is currently spendable.

        Args:
            tipHeight (int): The height of the best block.
        """
        raise Unimplemented("isSpendable not implemented")
    def key(self):
        """
        Return a key that is unique to this UTXO.

        Returns:
            str: A unique ID for this UTXO.
        """
        raise Unimplemented("key not implemented")
    @staticmethod
    def makeKey(txid, vout):
        """
        Make a key string by combining txid and vout.

        Args:
            txid (str): Transaction ID.
            vout (int): The transaction output index.

        Returns:
            str: txid and vout concatenated with a "#" in-between.
        """
        return txid + "#" + str(vout)

class Blockchain:
    """
    The Blockchain class defines an API to be implemented for each supported
    asset.
    """
    def __init__(self, db, params):
        """
        Args:
            db (KeyValueDatabase): A key-value database for storing blocks
                and transactions.
            params (object): Network parameters.
        """
        self.db = db
        self.params = params
        # The blockReceiver and addressReceiver will be set when the respective
        # subscribe* method is called.
        self.blockReceiver = None
        self.addressReceiver = None
    def subscribeBlocks(self, receiver):
        """
        Subscribe to new block notifications.

        Args:
            receiver (func(object)): A function or method that accepts the block
                notifications.
        """
        raise Unimplemented("subscribeBlocks not implemented")
    def subscribeAddresses(self, addrs, receiver):
        """
        Subscribe to notifications for the provided addresses.

        Args:
            addrs (list(str)): List of base-58 encoded addresses.
            receiver (func(object)): A function or method that accepts the address
                notifications.
        """
        raise Unimplemented("subscribeAddresses not implemented")
    def UTXOs(self, addrs):
        """
        UTXOs will produce any known UTXOs for the list of addresses.

        Args:
            addrs (list(str)): List of base-58 encoded addresses.
        """
        raise Unimplemented("UTXOs not implemented")
    def tx(self, txid):
        """
        tx will produce a transaction object which implements the Transaction
        API.

        Args:
            txid (str): Hex-encoded transaction ID.

        Returns:
            Transaction: A transction object which implements the Transaction
                API
        """
        raise Unimplemented("tx not implemented")
    def blockHeader(self, bHash):
        """
        blockHeader will produce a blockHeader implements the BlockHeader API.

        Args:
            bHash (str): The block hash of the block header.

        Returns:
            BlockHeader: An object which implements the BlockHeader API.
        """
        raise Unimplemented("blockHeader not implemented")
    def blockHeaderByHeight(self, height):
        """
        The blockHeader for the best block at the provided height.

        Args:
            height (int): The height of the block header.

        Returns:
            BlockHeader: An object which implements the BlockHeader API.
        """
        raise Unimplemented("blockHeaderByHeight not implemented")
    def bestBlock(self):
        """
        bestBlock will produce a decoded block as a Python dict.
        """
        raise Unimplemented("bestBlock not implemented")
    def sendToAddress(self, value, address, feeRate=None):
        """
        Send the amount in atoms to the specified address.

        Args:
            value (int): The amount to send, in atoms.
            address (str): The base-58 encoded address.
            feeRate (float): The reeRate (atoms/byte) to pay. (Optional. Will
                have a default value per-blockchain)

        Returns:
            Transaction: The newly created transaction.
            list(UTXO): The spent UTXOs.
            list(UTXO): Any newly generated UTXOs, such as change.
        """
        raise Unimplemented("sendToAddress not implemented")


class BlockHeader:
    """
    BlockHeader defines an API that must be implemented within Blockchain for
    block header objects.
    """
    def __init__(self, height, timestamp):
        self.height = height
        self.timestamp = timestamp
    @staticmethod
    def deserialize(b):
        """
        De-serialize the bytes into a BlockHeader.

        Args:
            b (ByteArray): A serialized block header.
        """
        raise Unimplemented("deserialize not implemented")
    def serialize(self):
        """
        Serialize the BlockHeader into a ByteArray.

        Returns:
            ByteArray: The serialized block header.
        """
        raise Unimplemented("serialize not implemented")
    def blockHash(self):
        """
        A hash of the serialized block.

        Returns:
            ByteArray: Hash of the serialized block header.
        """
        raise Unimplemented("blockHash not implemented")
    def id(self):
        """
        A string ID of the block, usually an encoding of the blockHash.

        Returns:
            str: A block ID.
        """
        raise Unimplemented("id not implemented")

class Transaction:
    """
    Transaction defines an API that must be implemented within Blockchain for
    transaction objects.
    """
    def __eq__(self, tx):
        """
        Check equality of this transaction with another.
        Args:
            tx (Transaction): Another object, presumably of the same class.
        """
        raise Unimplemented("__eq__ not implemented")
    def txHash(self):
        """
        A hash of the serialized transaction.

        Returns:
            ByteArray: The hashed transaction.
        """
        raise Unimplemented("txHash not implemented")
    def txid(self):
        """
        A transaction ID. Typically a string encoding of the txHash.

        Returns:
            str: The transaction id.
        """
        raise Unimplemented("txid not implemented")
    def serialize(self):
        """
        Serialize the transaction into bytes according to it's network protocol.

        Returns:
            ByteArray: The serialized transaction.
        """
        raise Unimplemented("serialize not implemented")
    @staticmethod
    def deserialize(b):
        """
        Create a Transaction-implementing object from a serialized transaction,
        such as that produced by serialize.

        Args:
            b (ByteArray): The serialized transaction.
        """
        raise Unimplemented("deserialize not implemented")

class Balance:
    """
    Balance defines an API for balance information.
    """
    def __init__(self, total=0, available=0):
        # The total is the sum of all transactions.
        self.total = total
        # The available is the amount available to spend immediately.
        self.available = available
    def __tojson__(self):
        """
        Balance must be json-encodable and registered with the tinyjson module.
        """
        raise Unimplemented("__tojson__ not implemented")
    @staticmethod
    def __fromjson__(obj):
        """
        Decode the Balance from the json encoding as returned by __tojson__
        """
        raise Unimplemented("__fromjson__ not implemented")

class Signals:
    """
    Signals defines an API for receiving asynchronous updates from a wallet
    or Blockchain.
    """
    def balance(self, balance):
        """
        A receiver for balance updates.

        Args:
            balance (Balance): The updated balance.
        """
        raise Unimplemented("Signals not implemented")

class PublicKey:
    """
    A public key structure.
    """
    def __init__(self, curve, x, y):
        """
        Args:
            curve (ECDSACurve): The ECDSA curve.
            x (int): The x coordinate.
            y (int): The y coordinate.
        """
        self.curve = curve
        self.x = x
        self.y = y
    def serializeCompressed(self):
        """
        Compressed form of the private key serialization.

        Returns:
            ByteArray: Compressed public key.
        """
        raise Unimplemented("serializeCompressed not implemented")
    def serializeUncompressed(self):
        """
        Uncompressed form of the public key serialization.

        Returns:
            ByteArray: Uncompressed public key
        """
        raise Unimplemented("serializeUncompressed not implemented")

class PrivateKey:
    """
    A private key structure. The associated public key information is stored as
    an attribute.
    """
    def __init__(self, curve, k, x, y):
        """
        Args:
            curve (ECDSACurve): The ECDSA curve.
            k (ByteArray): The private key.
            x (int): The x coordinate.
            y (int): The y coordinate.
        """
        self.key = k
        self.pub = PublicKey(curve, x, y)

class KeySource:
    """
    KeySource defines an API for retrieving `PrivateKey`s and change addresses.
    """
    def priv(self, addr):
        """
        Retreive the private key for a base-58 encoded address.

        Args:
            addr (str): An address.

        Returns:
            PrivateKey: Private key.
        """
        raise Unimplemented("KeySource not implemented")
    def internal(self):
        """
        Get a new internal address.

        Returns:
            str: A new base-58 encoded change address.
        """
        raise Unimplemented("internal not implemented")
