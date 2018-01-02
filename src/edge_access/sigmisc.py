import hashlib

class Hasher(object):
    """
    Adaptation of hashlib-based hash functions that return unicode-encoded hex- and base64-digest
    strings.
    """
    def __init__(self, data, h):
        if data is None:
            data = b''
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.h = h(data)

    @classmethod
    def md5(cls, data=''):
        return cls(data, hashlib.md5)

    @classmethod
    def sha256(cls, data=''):
        return cls(data, hashlib.sha256)

    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.h.update(data)

    def hexdigest(self):
        r = self.h.hexdigest()
        return r.decode('utf-8') if isinstance(r, bytes) else r

    def base64digest(self):
        r = base64.b64encode(self.h.digest())
        return r.decode('utf-8') if isinstance(r, bytes) else r


def get_sha256_hexdigest(content):
    return Hasher.sha256(content).hexdigest()


def get_md5_base64digest(content):
    return Hasher.md5(content).base64digest()


