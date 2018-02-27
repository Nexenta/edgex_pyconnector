#!/usr/bin/env python

from __future__ import absolute_import
import sys
import io
import simplejson
import json
import os
import itertools
import codecs
import hashlib
import requests
import urllib3
import urllib.parse as urlparse
import logging
import glob

# Added because some sites do not need ssl certification and that generates 
# warnings in the code.  Disable these warnings for now

from requests.packages.urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)    

from time import mktime, strptime
from datetime import datetime, timedelta
from requests_aws4auth import AWS4Auth

from lxml import etree
from io import StringIO, BytesIO

# ============================================================================
# internal globals
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB
DEFAULT_ENDPOINT="edge.nexenta.com"
DEFAULT_REGION="us-west-1"
EDGEX_ACCESS_LOG_NAME="edgex_access"
MAX_SINGLE_OBJ=5* 1024 * 1024 * 1024 # 5Gb

# ============================================================================
# buffer hash comutation

class edgex_hasher(object):
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


# ============================================================================
# logger

def find_loglevel(debug_level):
    if (debug_level == 0):
        return logging.DEBUG
    elif (debug_level == 1):
        return logging.INFO
    elif (debug_level == 2):
        return logging.WARNING
    elif (debug_level == 3):
        return logging.ERROR
    elif (debug_level == 4):
        return logging.CRITICAL
    else:
        return logging.NOTSET

class edgex_logger:
    def __init__(self, debug_level, logFile):
        file_format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s'
        if (debug_level >= 4):
            return
        log_level =  find_loglevel(debug_level)
        logging.basicConfig(level=log_level,
                             format=file_format,
                             datefmt='%m-%d %H:%M',
                             filename=logFile,
                             filemode='a')
        self.console = logging.StreamHandler()
        self.console.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.console.setFormatter(formatter)
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME)
        #rotateHandler = logging.handlers.RotatingFileHandler(logFile, maxBytes=1048576, backupCount=3)
        self.logger.addHandler(self.console)
        #self.logger.addHandler(rotateHandler)
    def enable(self, debug_level):
        logging.enable(find_loglevel(debug_level))
    def disable(self, debug_level):
        logging.disable(find_loglevel(debug_level))
    def log_info(self, logData):
        logging.info(logData)
    def log_debug(self, logData):
        logging.debug(logData)
    def log_error(self, logData):
        logging.error(logData)
    def log_critical(self, logData):
        logging.critical(logData)
    def log_warning(self, logData):
        logging.warning(logData)


# ============================================================================
# Error objects, Exceptions etc 

class edgex_error(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return "{name}: message: {message}".format(
            name=self.__class__.__name__,
            message=self.value
        )

class AccessDenied(edgex_error):
    pass
class InvalidURI(edgex_error):
    pass
class Redirect(edgex_error):
    pass
class ServiceError(edgex_error):
    pass
class CommandError(edgex_error):
    pass
class InvalidObject(edgex_error):
    pass
class InvalidObjectType(edgex_error):
    pass
class InvalidXML(edgex_error):
    pass
class HTTPErrorCode(edgex_error):
    pass

edgex_error_codes = {
        'AccessDenied': { 'class' : AccessDenied, 'message' : "Access is denied " },
        'InvalidURI': { 'class' : InvalidURI, 'message' : "URI is invalid " },
        'Redirect': { 'class' : Redirect, 'message' : "Temporary Redirect " },
        'ServiceError' : { 'class' : ServiceError, 'message' : "Service Configuration Error " },
        'CommandError' : { 'class' : CommandError, 'message' : "Command Configuration Error " },
        'InvalidObject' : { 'class' : InvalidObject, 'message' : "Object is invalid " },
        'InvalidObjectType' : { 'class' : InvalidObjectType, 'message' : "Object is invalid type" },
        'InvalidXML' : { 'class' : InvalidXML, 'message' : "XML is invalid " },
        'HTTPErrorCode' : { 'class' : HTTPErrorCode, 'message' : "HTTP Error " }
    }

def error_raise(ecode, emsg):
    raise(edgex_error_codes[ecode]['class'](edgex_error_codes[ecode]['message']))

ETREE_EXCEPTIONS = (SyntaxError, AttributeError, ValueError, TypeError)
S3_NS = {'s3' : 'http://s3.amazonaws.com/doc/2006-03-01/'}

class edgex_s3error(object):
    def __init__(self, response):
        self.error_content = response.text.encode('utf8')
        self.status_code = response.status_code
    def status(self):
        return self.status_code
    def error_text(self):
        eroot = etree.fromstring(self.error_content)
        code = eroot.find('Code').text
        output = 'Error code : {}\n'.format(code)
        message = eroot.find('Message').text
        output += 'Message : {}\n'.format(message)
        output += 'Status : {}\n'.format(self.status())
        return output

# ============================================================================
# parsers to S3 output

class edgex_s3list_parser(object):
    def __init__(self, xmlText):
        self.content = xmlText.encode('utf8')
        self.root = etree.fromstring(self.content)
        self.context = etree.iterwalk(self.root, events=("start", "end"))
    #  find an element of one value 
    #  <foo>
    #    <bar>
    #      <ID>dsdfsdfsds</ID>
    #    </bar>
    #  </foo>
    # find_element_one('foo/bar/ID') will return "dsdfsdfsds"
    def find_element_one(self, namepath, debug=False):
        namekeys = namepath.split("/")
        if (len(namekeys) == 0):
            return ""
        nmfound = {}
        nmfoundlist = []
        for action, elem in self.context:
            eltags = elem.tag.split("}")
            if debug:
                self.logger.debug(action + " : " + eltags[1] + " = " + elem.text)
            if (eltags[1] in namekeys):
                nmfound[eltags[1]] = 1
                if nmfound[eltags[1]] not in nmfoundlist:
                    nmfoundlist.append(nmfound[eltags[1]])
            # the last lement is what we want the value of
            if (eltags[1] == namekeys[-1]):
                return elem.text
    # Find a list of a certain key in a XML of list of objects
    # <foo>
    #   <bar>
    #     <cup>
    #       <color> brown </color>
    #     </cup>
    #     <cup>
    #       <color> red </color>
    #     </cup>
    #     <cup>
    #       <color> blue </color>
    #     </cup>
    #   <bar>
    # </foo>
    #
    # find_element_list('foo/bar/cup', 'color') will return [ 'brown', 'red'. 'blue' ]
    def find_element_list(self, namepath, pkey):
        namekeys = namepath.split("/")
        if (len(namekeys) == 0):
            return []
        nmfound = {}
        nmfoundlist = []
        for action, elem in self.context:
            eltags = elem.tag.split("}")
            if (eltags[1] == namekeys[-1]) and (action == "start") :
                    for child in elem:
                        tname = child.tag.split("}")[1]
                        if (tname == pkey):
                            nmfoundlist.append(child.text)
        return nmfoundlist

    def find_element_list_key(self, namepath, pkey):
        namekeys = namepath.split("/")
        if (len(namekeys) == 0):
            return []
        nmfoundlist = []
        for elem in self.root:
            eltags = elem.tag.split("}")
            if eltags[1] == namekeys[-1]:
                for child in elem:
                    if (child.tag.split("}")[1] == pkey):
                        nmfoundlist.append(child.text)
        return nmfoundlist

class edgex_s3parser(object):
    def __init__(self, root_name, element):
        self.root_name = root_name
        self.element = element
    def get_etag_elem(self, strict=True):
        return self.get_child_text('ETag', strict).replace('"', '')
    def get_int_elem(self, name):
        return int(self.get_child_text(name))
    def get_localized_time_elem(self, name):
        return _iso8601_to_localized_time(self.get_child_text(name))
    def text(self):
        return self.element.text
    @classmethod
    def fromstring(cls, root_name, data):
        try:
            return cls(root_name, cElementTree.fromstring(data))
        except ETREE_EXCEPTIONS as error:
            error_print(InvalidXML, 'XML is not parsable')
    def findall(self, name):
        return [
            edgex_s3parser(self.root_name, elem)
            for elem in self.element.findall('s3:{}'.format(name), S3_NS)
        ]
    def find(self, name):
        elt = self.element.find('s3:{}'.format(name), S3_NS)
        return edgex_s3parser(self.root_name, elt) if elt is not None else None
    def get_child_text(self, name, strict=True):
        if strict:
            try:
                return self.element.find('s3:{}'.format(name), S3_NS).text
            except ETREE_EXCEPTIONS as error:
                error_print(InvalidXML, 'Invalid XML --')
        else:
            return self.element.findtext('s3:{}'.format(name), None, S3_NS)

# ===========================================================================
# Core edgex_access objects 

# Each store definition
class edgex_store:
    def __init__(self, cfg):
        self.name = cfg['NAME']
        self.type = cfg['STORE_TYPE']
        if (self.type == "FS"):
            self.cwd = os.getcwd()
        self.access = cfg['ACCESS']
        self.secret = cfg['SECRET']
        self.endpoint = cfg['ENDPOINT']
        self.region = cfg['REGION']
        self.testbucket = cfg['BUCKET']
        self.token = cfg['TOKEN']
        self.use_ssl = cfg['SSL']
        self.tag = cfg['TAG']
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_store')
    def show(self):
        print(self.name + "\t" + self.type + "\t" + self.testbucket)
    def getType(self):
        return self.type
    def list_buckets(self, recursive=False):
        if (self.type == "S3"):
            auth = AWS4Auth(self.access, self.secret, self.region, 's3')
            try:
                response = requests.get(self.endpoint, auth=auth, verify=False)
                if response.status_code == 200:
                    self.logger.debug("GET " + self.endpoint + " " + str(response.status_code))
                    if (response.text.startswith("<!doctype html>") == True):
                        self.logger.error("Illegal HTML response on a GET: ") 
                        raise
                    eroot = edgex_s3list_parser(response.text)
                    top_name = eroot.find_element_one('ListAllMyBucketsResult/Owner/DisplayName')
                    blist = eroot.find_element_list('ListAllMyBucketsResult/Buckets/Bucket', 'Name')
                    return top_name, blist
                else:
                    self.logger.error("GET " + self.endpoint + " " + str(response.status_code))
                    s3err = edgex_s3error(response) 
                    self.logger.error(s3err.error_text())
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                return
        elif (self.type == "FS"):
            # show subdirs only and no dot files or dirs
            file_list = [ name for name in os.listdir(self.testbucket) if (os.path.isdir(os.path.join(self.testbucket, name))  and (not name.startswith('.'))) ]
            file_list.sort()
            return self.testbucket, file_list
        else:
            self.logger.error("list_buckets type: " + self.type + " unknown ")


# ============================================================================
# complete configuration


class edgex_config:
    def __init__(self):
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_config')
        self.store_dict = {}
        self.debug_level = 4
        self.primary = ""
        self.configured = False

    def configure(self):
        if not self.configured:
            stores = self.cfg_data['stores']
            #self.store_list = []
            for x in stores:
                self.store_dict[ x['NAME'] ] = edgex_store(x)
            if self.cfg_data['PRIMARY']:
                self.primary = self.cfg_data['PRIMARY']
            if self.cfg_data['DEBUG']:
                self.debug_level = self.cfg_data['DEBUG']
            if self.cfg_data['HOME']:
                self.home = self.cfg_data['HOME']
            else:
                self.logger.error('Missing HOME in configuration')
                return
            self.configured = True
            self.logger.info("configuration  loaded")
        else:
            self.logger.info('already configured')

    def show_stores(self):
        if not self.configured:
            self.logger.error("Not configured")
            return
        for k in self.store_dict:
            self.store_dict[k].show()

    def load_file(self, fileName):
        try:
            dff = open(fileName)
            self.cfg_data = json.load(dff)
            self.logger.info(fileName + " loaded")
            self.service_name = self.cfg_data['PRIMARY']
        except FileNotFoundError:
            self.logger.error("File not found : " + fileName)
            raise
        except json.decoder.JSONDecodeError:
            self.logger.error("JSON format error ")
        except:
            self.logger.error("Unexpected Error: ", sys.exc_info()[0])
            raise
        self.configure()

    @classmethod
    def fromstring(self, config_str):
        self.configured = False
        try:
            self.cfg_data = json.loads(config_str)
            self.service_name = self.cfg_data['PRIMARY']
        except json.decoder.JSONDecodeError:
            self.logger.error("JSON format error ")
        except:
            self.logger.error("Unexpected Error: ", sys.exc_info()[0])
            raise
        self.configure()

    def save_file(self, fileName):
        try:
            jsondata = simplejson.dumps(self.cfg_data, indent=4, skipkeys=True, sort_keys=True)
            fd = open(fileName, 'w')
            fd.write(jsondata)
            fd.close()
            self.logger.info("File " + fileName + " saved")
        except:
            self.logger.error("ERROR writing " +  fileName)

    def getStore(self, store_name):
        try:
            store = self.store_dict[store_name]
            return store
        except:
            return None
    def saveCfg(self, fileName):
        return self.save_file(fileName)
    def setPrimary(self, store_name):
        if self.store_dict[store_name]:
            self.primary = store_name
    def getPrimary(self):
        return self.primary
    def getPrimaryStore(self):
        if self.primary:
            return self.store_dict[self.primary]
        else:
            return None
    def getType(self, store_name):
        return self.store_dict[store_name]['STORE_TYPE']
    def getEndpoint(self, store_name):
        return self.store_dict[store_name]['ENDPOINT']
    def getRegion(self, store_name):
        return self.store_dict[store_name]['REGION']
    def getSecretKey(self, store_name):
        return self.store_dict[store_name]['SECRET']
    def getAccessKey(self, store_name):
        return self.store_dict[store_name]['ACCESS']
    def getTestBucket(self, store_name):
        return self.store_dict[store_name]['BUCKET']
    def getHome(self):
        for k in self.store_dict:
            store = self.store_dict[k]
            if ( (store.name == "HOME") and (store.type == "FS") ):
                return store
# ============================================================================
# the main edgex_obj that is geared torawrds doing I/O to a Store
#
class edgex_obj:
    def __init__(self, store, name):
        self.oname = name
        self.isfolder = False
        self.store = store
        if ((self.store.type == "S3") and self.oname.endswith("/")):
                self.isfolder = True
        if ((self.store.type == "FS") and os.path.isdir(self.oname)):
                self.isfolder = True

        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_obj')
        self.logger.info(store.name + " " + self.oname)
        if (store.type == "S3"):
            bname = name.split("/")
            if (bname[0] is None):
                self.logger.error(name + " is not valid")
            else:
                self.bucketName = bname[0]
        elif (store.type == "FS"):
            self.bucketName = store.testbucket
        else:
            raise 
    def show(self):
        print(self.oname + " " + self.store.type)
        print(self.store_cfg)
        print(self.objname)

    def getStore(self):
        return self.store

    def get(self):
        if (self.store.type == "FS"):
            file_size = os.stat(self.oname).st_size
            if (file_size > MAX_SINGLE_OBJ):
                self.logger.error('MaxObjectSize', objtype)
                raise
            file_data = io.open(self.oname, mode='rb')
            fdata_now = file_data.read(file_size)
            return fdata_now
        elif (self.store.type == "S3"):
            objp = self.oname.split("/")
            bucketName = objp[0]
            objpath = "/".join(objp[1:])
            auth = AWS4Auth(self.store.access, self.store.secret, \
                    self.store.region, 's3')
            url = self.store.endpoint + "/" + bucketName + "/" + objpath
            try:
                response =  requests.get(url, auth=auth, verify=False)
                if response.status_code == 200:
                    if response.ok:
                        self.logger.debug("GET " + url + " " + str(response.status_code))
                        return response.content
                    else:
                        self.logger.error("GET " + url + " " + str(response.status_code))
                        self.logger.error("File: " + fileName)
                        raise requests.HTTPError(response.text)
                else:
                    s3err = edgex_s3error(response) 
                    self.logger.error(s3err.error_text())
                    raise requests.HTTPError(response.text)
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            self.logger.error('InvalidObject', objtype)
            raise InvalidObjectType(str(objtype))

    def put(self, databuf):
        if (self.store.type == "FS"):
            if not os.path.exists(os.path.dirname(self.oname)):
                try:
                    os.makedirs(os.path.dirname(self.oname))
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            open(self.oname, 'wb').write(databuf)
            return
        elif (self.store.type == "S3"):
            objp = self.oname.split("/")
            bucketName = objp[0]
            objpath = "/".join(objp[1:])
            auth = AWS4Auth(self.store.access, self.store.secret, \
                    self.store.region, 's3')
            url = self.store.endpoint + "/" + bucketName + "/" + objpath
            databuf_size = len(databuf)
            metaonheader = {}
            metaonheader['Content-Type'] = 'application/octet-stream'
            headers = {
                'Content-Length': str(databuf_size),
            }
            headers.update(metaonheader)
            sha256_hex = edgex_hasher.sha256(databuf).hexdigest()
            try:
                response = requests.put(url, data=databuf, headers=headers, auth=auth, verify=False)
                if response.status_code == 200:
                    if response.ok:
                        self.logger.debug("PUT " + url + " " + str(response.status_code))
                        return
                    else:
                        self.logger.error("PUT " + url + " " + str(response.status_code))
                        raise requests.HTTPError(response.text)
                else:
                    s3err = edgex_s3error(response) 
                    self.logger.error(s3err.error_text())
                    raise requests.HTTPError(response.text)
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            self.logger.error('InvalidObject', objtype)
            raise InvalidObjectType(str(objtype))

    def remove(self):
        if (self.store.type == "FS"):
            if os.path.exists(self.oname):
                os.remove(self.oname)
        elif (self.store.type == "S3"):
            objp = self.oname.split("/")
            bucketName = objp[0]
            objpath = "/".join(objp[1:])
            auth = AWS4Auth(self.store.access, self.store.secret, \
                    self.store.region, 's3')
            url = self.store.endpoint + "/" + bucketName + "/" + objpath
            try:
                response =  requests.delete(url, auth=auth, verify=False)
                if response.status_code == 200 or response.status_code == 204:
                    if response.ok:
                        self.logger.debug("DELETE " + url + " " + str(response.status_code))
                        return
                    else:
                        self.logger.error("DELETE " + url + " " + str(response.status_code))
                        raise requests.HTTPError(response.text)
                else:
                    self.logger.error("DELETE " + url + " " + str(response.status_code))
                    s3err = edgex_s3error(response) 
                    if s3err.error_code() == 'NoSuchKey':
                        return
                    else:
                        self.logger.error(s3err.error_text())
                        raise requests.HTTPError(response.text)
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            self.logger.error('InvalidObject', objtype)
            raise InvalidObjectType(str(objecttype))

    def exists(self):
        if (self.store.type == "FS"):
            return os.path.exists(self.oname)
        elif (self.store.type == "S3"):
            objp = self.oname.split("/")
            bucketName = objp[0]
            objpath = "/".join(objp[1:])
            auth = AWS4Auth(self.store.access, self.store.secret, \
                    self.store.region, 's3')
            url = self.store.endpoint + "/" + bucketName + "/" + objpath
            try:
                response =  requests.head(url, auth=auth, verify=False)
                if response.status_code == 200:
                    if response.ok:
                        self.logger.debug("HEAD " + url + " " + str(response.status_code))
                        return True
                    else:
                        self.logger.debug("HEAD " + url + " " + str(response.status_code))
                        return False
                else:
                    self.logger.error("HEAD " + url + " " + str(response.status_code))
                    #s3err = edgex_s3error(response) 
                    #self.logger.error(s3err.error_text())
                    return False
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
            except Exception as e:
                self.logger.error(str(e))
            return False
        else:
            self.logger.error('InvalidObject', objtype)
            return False

    def list(self):
        final_list = []
        if (self.store.type == "FS"):
            if os.path.isdir(self.oname):
                final_list = os.listdir(self.oname)
                i=0
                for f in final_list:
                    if os.path.isdir(self.oname + "/" + f):
                        final_list[i] = f + "/"
                    i+=1
            return final_list
        elif (self.store.type == "S3"):
            if not self.oname.endswith("/"):
                self.logger.error(self.oname + " does not end with / ")
                return final_list
            objp = self.oname.split("/")
            bucketName = objp[0]
            objpath = "/".join(objp[1:])
            auth = AWS4Auth(self.store.access, self.store.secret, self.store.region, 's3')
            url = self.store.endpoint + "/" + bucketName + "/" + "?list-type=2&prefix=" + objpath + "&delimiter=/"
            try:
                response =  requests.get(url, auth=auth, verify=False)
                if response.status_code == 200:
                    if response.ok:
                        if response.headers['Content-Type'] == 'application/xml':
                            eroot = edgex_s3list_parser(response.text)
                            top_name = eroot.find_element_one('ListBucketsResult/Name')
                            contents = eroot.find_element_list('ListBucketsResult/Contents', 'Key')
                            subdir = eroot.find_element_list_key('ListBucketsResult/CommonPrefixes','Prefix')
                            for content in contents:
                                final_list.append(content)
                            for mdir in subdir:
                                final_list.append(mdir)
                            return final_list
                        else:
                            self.logger.error("Unable to parse:")
                            self.logger.error(response.text)
                            self.logger.error(objname + "\t\t" + response.headers['Content-Length'] + "\t\t" + response.headers['Last-Modified'])
                            return final_list
                    else:
                        self.logger.error("HEAD " + url + " " + str(response.status_code))
                        raise requests.HTTPError(response.text)
                else:
                    self.logger.error("Error: " + str(response.status_code))
                    raise requests.HTTPError(response.text)
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            self.logger.error('InvalidObject', objtype)
            raise InvalidObjectType(str(objtype))
    
    def read(self):
        return self.get()
    def write(self, buffer):
        return self.put(buffer)

    def metainfo(self):
        if (self.store.type == "FS"):
            metadata = { f:os.stat(f) for f in glob.glob('*') }
            return metadata
        elif (self.store.type == "S3"):
            objp = self.oname.split("/")
            bucketName = objp[0]
            objpath = "/".join(objp[1:])
            auth = AWS4Auth(self.store.access, self.store.secret, \
                    self.store.region, 's3')
            url = self.store.endpoint + "/" + bucketName + "/" + objpath
            try:
                response =  requests.head(url, auth=auth, verify=False)
                if response.status_code == 200:
                    if response.ok:
                        self.logger.debug("HEAD " + url + " " + str(response.status_code))
                        return response.headers
                    else:
                        self.logger.error("HEAD " + url + " " + str(response.status_code))
                        raise requests.HTTPError(response.text)
                else:
                    raise requests.HTTPError(response.text)
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            self.logger.error('InvalidObject', objtype)
            raise InvalidObjectType(str(objtype))

if __name__ == "__main__":
    pass
