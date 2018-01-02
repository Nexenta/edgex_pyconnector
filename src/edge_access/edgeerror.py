import sys
import json
import os

class edge_error(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "{name}: message: {message}".format(
            name=self.__class__.__name__,
            message=self.value
        )

class AccessDenied(edge_error):
    pass
class InvalidURI(edge_error):
    pass
class Redirect(edge_error):
    pass
class ServiceError(edge_error):
    pass
class CommandError(edge_error):
    pass
class InvalidObject(edge_error):
    pass
class InvalidXML(edge_error):
    pass

edge_error_codes = {
        'AccessDenied': { 'class' : AccessDenied, 'message' : "Access is denied " },
        'InvalidURI': { 'class' : InvalidURI, 'message' : "URI is invalid " },
        'Redirect': { 'class' : Redirect, 'message' : "Temporary Redirect " },
        'ServiceError' : { 'class' : ServiceError, 'message' : "Service Configuration Error " },
        'CommandError' : { 'class' : CommandError, 'message' : "Command Configuration Error " },
        'InvalidObject' : { 'class' : InvalidObject, 'message' : "Object is invalid " },
        'InvalidXML' : { 'class' : InvalidXML, 'message' : "XML is invalid " }
    }

def error_raise(ecode, emsg):
    raise(edge_error_codes[ecode]['class'](edge_error_codes[ecode]['message']))


