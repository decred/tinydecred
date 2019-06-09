from tinydecred import crypto
from pydecred import helpers
import os
import json

ID_TAG = "tinywallet"
VERSION = "0.0.1"

def createNewKeys():
    return {
        "priv": "abc",
        "pub": "def"
    }

class Wallet:
    def __init__(self):
        self.path = None
        self.file = None
    def create(self, path, password):
        self.path = path
        if os.path.isfile(self.path):
            raise FileExistsError("wallet already exists at path %s" % self.path)
        keys = createNewKeys()
        self.file = {
            "tag": ID_TAG,
            "keys": keys,
            "version": VERSION,
            "tx": {}
        }
        self.save(password)
    def save(self, password):
        if self.file is None:
            raise TypeError("no wallet has been loaded")
        encrypted = crypto.AES.encrypt(password, json.dumps(self.file))
        helpers.saveFile(self.path, encrypted)
    def open(self, path, password):
        """
        open must be called before any other methods
        """
        self.path = path
        if not os.path.isfile(self.path):
            raise FileNotFoundError("no wallet found at %s" % self.path)
        with open(self.path, 'r') as f:
            encrypted = f.read()
        wallet = json.loads(crypto.AES.decrypt(password, encrypted))
        if wallet["tag"] !=ID_TAG:
            raise IOError("unable to open wallet with provided password")
        self.file = wallet
    def close(self):
        self.file = None
