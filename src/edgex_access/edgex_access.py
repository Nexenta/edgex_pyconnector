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
import re

import threading
from concurrent.futures import ThreadPoolExecutor, \
        ProcessPoolExecutor, \
        as_completed

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
logger_level = { 0 : logging.DEBUG, 1 : logging.INFO, 2 : logging.WARNING, 3 : logging.ERROR, 4 : logging.CRITICAL }

class edgex_logger:
    """
    edgex_logger : create a log for edgex module debugging and errors
    """
    def __init__(self, debug_level, logFile):
        file_format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s'
        if (debug_level >= 4):
            return
        log_level =  logger_level[debug_level]
        logging.basicConfig(level=log_level, format=file_format, datefmt='%m-%d %H:%M',
                             filename=logFile,
                             filemode='a')
        self.console = logging.StreamHandler()
        self.console.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.console.setFormatter(formatter)
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME)
        self.logger.addHandler(self.console)
        #rotateHandler = logging.handlers.RotatingFileHandler(logFile, maxBytes=1048576, backupCount=3)
        #self.logger.addHandler(rotateHandler)

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
class InvalidStore(edgex_error):
    pass
class InvalidCommand(edgex_error):
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
        'HTTPErrorCode' : { 'class' : HTTPErrorCode, 'message' : "HTTP Error " },
        'InvalidStore' : { 'class' : InvalidStore, 'message' : "Invalid Store  " },
        'InvalidCommand' : { 'class' : InvalidCommand, 'message' : "Invalid Command  " }
    }

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
    def __init__(self):
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_store')
        
    def fromjson(self, cfg):        
        self.name = cfg['NAME']
        self.type = cfg['STORE_TYPE']
        if (self.type == "FS"):
            self.cwd = os.getcwd()
        self.default_bucket = cfg['BUCKET']
        self.bucket = self.default_bucket
        self.token = cfg['TOKEN']
        self.tag = cfg['TAG']
        if (self.type != "FS"):
            self.access = cfg['ACCESS']
            self.secret = cfg['SECRET']
            self.endpoint = cfg['ENDPOINT']
            self.region = cfg['REGION']
            self.use_ssl = cfg['SSL']

    def create(self, name, store_type, bucket, access=None, secret=None,\
            endpoint=None, region=None, token=None, tag=None):
        self.name = name
        self.type = store_type
        if (self.type == "FS"):
            self.cwd = os.getcwd()
        self.access = access
        self.secret = secret
        self.endpoint = endpoint
        self.region = region
        self.bucket = bucket
        self.token = token 
        self.tag = tag 

    def get_name(self):
        return self.name
    def get_type(self):
        return self.type
    def get_default_bucket(self):
        return self.bucket
    def set_local_pwd(self):
        self.bucket = os.getcwd()
        self.default_bucket = self.bucket
    def list_buckets(self):
        if (self.type == "S3"):
            auth = AWS4Auth(self.access, self.secret, self.region, 's3')
            try:
                response = requests.get(self.endpoint, auth=auth, verify=False)
                if response.status_code == 200:
                    self.logger.debug("GET " + self.endpoint + " " + str(response.status_code))
                    if (response.text.startswith("<!doctype html>") == True):
                        self.logger.error("Illegal HTML response on a GET: ") 
                        raise InvalidXML(response.text)
                    eroot = edgex_s3list_parser(response.text)
                    top_name = eroot.find_element_one('ListAllMyBucketsResult/Owner/DisplayName')
                    blist = eroot.find_element_list('ListAllMyBucketsResult/Buckets/Bucket', 'Name')
                    return top_name, blist
                else:
                    self.logger.error("GET " + self.endpoint + " " + str(response.status_code))
                    s3err = edgex_s3error(response) 
                    self.logger.error(s3err.error_text())
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
        elif (self.type == "FS"):
            # show subdirs only and no dot files or dirs
            file_list = [ name for name in os.listdir(self.testbucket) if (os.path.isdir(os.path.join(self.testbucket, name))  and (not name.startswith('.'))) ]
            file_list.sort()
            return self.testbucket, file_list
        else:
            raise InvalidStore(self.type)

# ============================================================================
# complete configuration

class edgex_config:
    def __init__(self):
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_config')
        self.store_dict = {}
        self.debug_level = 4
        self.primary = ""
        self.configured = False
        self.syncio = "SYNC"
    def configure(self):
        if not self.configured:
            stores = self.cfg_data['stores']
            #self.store_list = []
            for x in stores:
                self.store_dict[ x['NAME'] ] = edgex_store()
                self.store_dict[ x['NAME'] ].fromjson(x)
            if self.cfg_data['PRIMARY']:
                self.primary = self.cfg_data['PRIMARY']
            if self.cfg_data['DEBUG']:
                self.debug_level = self.cfg_data['DEBUG']
            if self.cfg_data['SYNCIO']:
                self.syncio = self.cfg_data['SYNCIO']
            self.configured = True
            self.logger.info("configuration loaded")
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
            raise FileNotFound(filename)
        except json.decoder.JSONDecodeError:
            self.logger.error("JSON format error ")
            dff.close()
            raise JsonFormat(filename)
        except:
            self.logger.error("Unexpected Error: ", sys.exc_info()[0])
            dff.close()
            raise UnexpectedError(sys.exc_info()[0])
        self.configure()
        dff.close()
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
            raise UnexpectedError(sys.exc_info()[0])
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
    def get_stores(self):
        ret = []
        for k in self.store_dict:
            store = self.store_dict[k]
            ret.append(store.name)
        return ret
    def get_store(self, store_name):
        try:
            store = self.store_dict[store_name]
            return store
        except:
            return None
    def get_primary_store(self):
        if self.primary:
            return self.store_dict[self.primary]
        else:
            return None
    def get_local_pwd(self):
        store = edgex_store()
        store.create("local", "FS", os.getcwd())
        self.store_dict["local"] = store
        return store


# ===========================================================================
# edgex_object
# 
class edgex_object:
    def __init__(self, cfg, name, store=None, local_pwd=False):
        self.oname = name
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_obj')
        t = datetime.utcnow()
        self.amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

        if store is None:
            is_store = False
        else:
            is_store = True

        # first we figure out the stores, parse the names etc
        sname = self.oname.split(":")
        if (len(sname) == 2):
            if is_store is False:
                store = cfg.get_store(sname[0])
                if store is None:
                    if local_pwd is False:
                        self.logger.error("Error: " + self.oname)
                        raise InvalidStore(sname[0] + ": Store not found")
                    else:
                        store = cfg.get_local_pwd()
                        is_store=True
                else:
                    is_store=True

            if (sname[1].startswith('//')):
                bpath = re.sub('//', '/',sname[1])
            else:
                bpath = self.oname
        elif (len(sname) == 1):
            if is_store is False:
                store = cfg.get_store(sname[0])
                if store is None:
                    if local_pwd is False:
                        self.logger.error("Error: " + self.oname)
                        raise InvalidStore(sname[0] + ": Store not found")
                    else:
                        store = cfg.get_local_pwd()
                        is_store=True
                else:
                    is_store=True

            if (sname[0].startswith('//')):
                bpath = re.sub('//', '/',sname_1[0])
            else:
                bpath = self.oname
        else:
            if local_pwd:
                store = cfg.get_local_pwd()
                is_store=True
        #
        if is_store is False:
            raise InvalidStore("No store defined: " + name)

        self.store = store
        self.isfolder = False
        if (self.store.get_type() == "S3"):
            if self.oname.endswith("/"):
                self.isfolder = True

        if (self.store.get_type() == "FS"):
            if os.path.isdir(self.oname):
                self.isfolder = True
            if os.path.isfile(self.oname):
                self.islocal = True

        # now initialize the bucket, name itself 
        bname = bpath.split("/")
        if (len(bname) == 2):
            self.bucket_name = bname[1]
            self.obj_name = ""
        elif (len(bname) > 2):
            self.bucket_name = bname[1]
            self.obj_name = "/".join(bname[2:])
        else:
            if local_pwd is False:
                self.logger.error("Error: " + bpath)
                raise InvalidStore(name + ": Store not found")
            else:
                store = cfg.get_local_pwd()
                self.obj_name = bpath

        if ((self.store.type == "FS") and (local_pwd == True)):
            self.bucket_name = os.getcwd()
            self.obj_name = bpath

        if len(self.bucket_name) == 0:
            self.logger.error("No Bucket name")

        self.logger.info("OBJECT : " + self.pathname())

    def get_store(self):
        return self.store
    def store_type(self):
        return self.store.type

    def bucketname(self):
        return self.bucket_name
    def objname(self):
        return self.obj_name

    def auth(self):
        auth = AWS4Auth(self.store.access, self.store.secret, self.store.region, 's3')
        return auth

    # return only the storename://bucketname of this object
    #
    def basename(self):
        if (self.store.get_name() != "local"):
            fpath = self.store.get_name() + "://" + self.bucket_name + "/" 
        else:
            fpath = self.store.get_name() + ":/" + self.bucket_name + "/" 
        return fpath

    def stat(self, create=False):
        if (self.store_type() == "FS"):
            file_found = os.path.exists(self.pathname())
            if ((file_found is False) and (create is True) and self.obj_name.endswith("/")):
                self.logger.info("mkdir " + self.pathname())
                os.makedirs(self.pathname())
            else:
                return file_found
        else:
            self.logger.error("Error: No stat on store_type: " + self.store_type())
            raise InvalidStore(str(sef.store_type()))

    def pathname(self):
        if (self.store_type() == "FS"):
            if self.bucket_name and self.obj_name :
                fpath = self.bucket_name + "/" + self.obj_name
            else:
                fpath = self.store.default_bucket + "/" + self.obj_name
        elif (self.store_type() == "S3"):
            if self.bucket_name and self.obj_name :
                fpath = self.store.endpoint + "/" + self.bucket_name + "/" + self.obj_name
            else:
                fpath = self.store.default_bucket
        else:
            self.logger.error("Error: store_type: " + self.store_type())
            raise InvalidStore(str(sef.store_type()))
        return fpath
# ============================================================================
# edgex_operations
#
valid_ops = [ "list", "get", "put", "meta", "exists", "delete" ]
class edgex_operation:
    def __init__(self, opname):
        found=False
        for op in valid_ops:
            if (opname.lower() == op.lower()):
                found = True
        if not found:
            raise InvalidCommand(opname)
        self.opname = opname
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_objname')

    def list(self, obj):
        final_list = []
        if (obj.store_type() == "FS"):
            if obj.isfolder:
                final_list = os.listdir(obj.pathname())
                i=0
                for f in final_list:
                    if os.path.isdir(obj.pathname() + "/" + f):
                        final_list[i] = f + "/"
                    i+=1
            else:
                if os.path.isfile(obj.pathname()):
                    final_list.append(obj.pathname())
            return final_list
        elif (obj.store_type() == "S3"):
            if not obj.isfolder:
                # for a single object , check if it is there 
                # and return only the object
                isthere = self.exists(obj)
                if isthere:
                    final_list.append(obj.pathname())
            else:
                # in case we received no bucketname and no object name
                if not obj.bucket_name and not obj.obj_name:
                    top_name, final_list = obj.store.list_buckets()
                    return final_list
                # list the content of the folder and return 
                url = obj.store.endpoint + "/" + obj.bucket_name + "/" + "?list-type=2&prefix=" + obj.obj_name + "&delimiter=/"
                try:
                    response =  requests.get(url, auth=obj.auth(), verify=False)
                    if response.status_code != 200 or (not response.ok):
                        raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))

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
                except requests.exceptions.RequestException as e:
                    self.logger.error(str(e))
                    raise e
                except Exception as e:
                    self.logger.error(str(e))
                    raise e
            return final_list
        else:
            raise InvalidStore(obj.store_type())

    def exists(self, obj):
        if (obj.store.type == "FS"):
            return os.path.exists(obj.pathname())
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.head(url, auth=obj.auth(), verify=False)
                if response.status_code != 200 or (not response.ok):
                    self.logger.error("HEAD " + url + " " + str(response.status_code))
                    self.logger.error(response.text)
                    #s3err = edgex_s3error(response) 
                    #self.logger.error(s3err.error_text())
                    return False
                else:
                    self.logger.debug("HEAD " + url + " " + str(response.status_code))
                    return True
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
            except Exception as e:
                self.logger.error(str(e))
            return False
        else:
            raise InvalidStore(obj.store_type())

    def meta(self, obj):
        if (obj.store.type == "FS"):
            metadata = { f:os.stat(f) for f in glob.glob('*') }
            return metadata
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.head(url, auth=obj.auth(), verify=False)
                if (response.status_code != 200) or (not response.ok):
                    self.logger.error("HEAD " + url + " " + str(response.status_code))
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                else:
                    self.logger.debug("HEAD " + url + " " + str(response.status_code))
                    return response.headers
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    def get(self, obj):
        if (obj.store.type == "FS"):
            file_size = os.stat(obj.pathname()).st_size
            if (file_size > MAX_SINGLE_OBJ):
                self.logger.error('MaxObjectSize', objtype)
                raise
            file_data = io.open(obj.pathname(), mode='rb')
            fdata_now = file_data.read(file_size)
            return fdata_now
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.get(url, auth=obj.auth(), verify=False)
                if (response.status_code != 200) or (not response.ok):
                    self.logger.error("GET " + url + " " + str(response.status_code))
                    self.logger.error("File: " + fileName)
                    s3err = edgex_s3error(response) 
                    self.logger.error(s3err.error_text())
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                elif (response.status_code == 200) and (response.ok):
                    self.logger.debug("GET " + url + " " + str(response.status_code))
                    return response.content
                else:
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    # TODO: move databuf as a field inside obj 
    def put(self, obj, databuf):
        if (obj.store.type == "FS"):
            if not os.path.exists(os.path.dirname(obj.pathname())):
                try:
                    os.makedirs(os.path.dirname(obj.pathname()))
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            open(obj.pathname(), 'wb').write(databuf)
            return
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            databuf_size = len(databuf)
            metaonheader = {}
            metaonheader['Content-Type'] = 'application/octet-stream'
            headers = {
                'Content-Length': str(databuf_size),
            }
            headers.update(metaonheader)
            sha256_hex = edgex_hasher.sha256(databuf).hexdigest()
            try:
                response = requests.put(url, data=databuf, headers=headers, auth=obj.auth(), verify=False)
                if response.status_code == 200:
                    if response.ok:
                        self.logger.debug("PUT " + url + " " + str(response.status_code))
                        return
                    else:
                        self.logger.error("PUT " + url + " " + str(response.status_code))
                        raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                else:
                    s3err = edgex_s3error(response) 
                    self.logger.error(s3err.error_text())
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
            except requests.exceptions.RequestException as e:
                self.logger.error(str(e))
                raise e
            except Exception as e:
                self.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    def remove(self, obj):
        if (obj.store.type == "FS"):
            if os.path.isfile(obj.pathname()):
                os.remove(obj.pathname())
                return
            if os.path.isdir(obj.pathname()):
                dentries = os.listdir(obj.pathname())
                if (len(dentries) == 0):
                    os.rmdir(obj.pathname())
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.delete(url, auth=obj.auth(), verify=False)
                if response.status_code == 200 or response.status_code == 204:
                    if response.ok:
                        self.logger.debug("DELETE " + url + " " + str(response.status_code))
                        return
                    else:
                        self.logger.error("DELETE " + url + " " + str(response.status_code))
                        raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
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
            raise InvalidStore(obj.store_type())

if __name__ == "__main__":
    pass
