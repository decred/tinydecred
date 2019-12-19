"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details
"""

import json

JSONDecodeError = json.JSONDecodeError

_types = {}


def register(cls, k):
    """
    Registered types will be checked for compliance with the JSONMarshaller.
    When an object of a registered type is dump'ed, it's __tojson__ method
    will be called to retreive the JSON-compliant dict. A special attribute
    _jt_ is quietly added during encoding. When that JSON object
    is decoded with load, the type is converted using the static __fromjson__
    method.
    """
    cls.__jsontag__ = k
    if k in _types:
        raise Exception("tinyjson: mutliple attempts to register class %s" % k)
    _types[k] = cls


def decoder(obj):
    if "_jt_" in obj:
        for k in obj.keys():
            if isinstance(obj[k], dict):
                obj[k] = decoder(obj[k])
        return _types[obj["_jt_"]].__fromjson__(obj)
    return obj


def load(s):
    """
    Turn the string into an object with the custon decoder.
    """
    return json.loads(s, object_hook=decoder)


def loadFile(filepath):
    """
    Load the JSON with a decoder. This method uses load, and therefore
    the custom decoder which recognizes registered types.
    """
    with open(filepath, "r") as f:
        return load(f.read())


class Encoder(json.JSONEncoder):
    """
    A custom encoder that works with classes implementing the JSONMarshaller interface.
    A class implementing the JSONMarshaller interface will have two methods.
    1. __fromjson__: @staticmethod. A method that will take a freshly decoded
        dict and return an instance of its class.
    2. __tojson__: A method that returns an encodable version of itself,
        probably a dict.
    """

    def default(self, obj):
        if hasattr(obj.__class__, "__jsontag__"):
            encoded = obj.__tojson__()
            encoded["_jt_"] = obj.__class__.__jsontag__
            return encoded
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def dump(thing, **kwargs):
    """
    Encode the thing to JSON with the JSONCoder.
    """
    return json.dumps(thing, cls=Encoder, **kwargs)


def save(filepath, thing, **kwargs):
    """
    Save the object to JSON with custom encoding from encodeJSON
    """
    with open(filepath, "w") as f:
        f.write(dump(thing, **kwargs))


def dumpFmt(thing):
    """
    A pretty-printed string, with newlines and sorted keys.
    """
    return dump(thing, indent=4, sort_keys=True)
