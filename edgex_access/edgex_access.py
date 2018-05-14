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
import random 

# Added because some sites do not need ssl certification and that generates 
# warnings in the code.  Disable these warnings for now
from requests.packages.urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)    

import time
from time import mktime, strptime
from datetime import datetime, timedelta
from requests_aws4auth import AWS4Auth

from lxml import etree
from io import StringIO, BytesIO
import re


#
# Following was added when threading was introduced here
#
from queue import Queue
import threading
from threading import Thread
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, \
        ProcessPoolExecutor, \
        as_completed
# ============================================================================

"""
.. module:: edgex_access
    :platform: OS X, Ubuntu
    :synopsis: module that enables S3 protocol access for I/O

.. moduleauthor:: Nexenta Systems

"""

# ============================================================================
# internal globals
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB
DEFAULT_ENDPOINT="edge.nexenta.com"
DEFAULT_REGION="us-west-1"
EDGEX_ACCESS_LOG_NAME="edgex_access"
MAX_SINGLE_OBJ=5* 1024 * 1024 * 1024 # 5Gb
# ============================================================================

# buffer hash computation

class edgex_hasher(object):
    """ Class that performs the hashlib-based hash calculations
    .. note :: This class is a set of helper methods around 
               the real methods that compute the hash 
               Adaptation of hashlib-based hash functions that 
               return unicode-encoded hex- and base64-digest strings.
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
    """ Class that allows for logging and creating logs 
    .. note :: set of methods to do logging based on the 
               log level specified.
               logging can do logging based on the module
    """
    def __init__(self, debug_level, logFile):
        """ logger initialization method
        Args:
            debug_level; log level
            logFile: name of the file to send logs to 
        """
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
        self.islocal_store = False
        
    def fromjson(self, cfg):        
        self.name = cfg['NAME']
        self.type = cfg['STORE_TYPE']
        if (self.type == "FS"):
            self.cwd = os.getcwd()
        self.bucket = cfg['BUCKET']
        self.token = cfg['TOKEN']
        self.tag = cfg['TAG']
        if (self.type == "S3"):
            self.access = cfg['ACCESS']
            self.secret = cfg['SECRET']
            self.endpoint = cfg['ENDPOINT']
            self.region = cfg['REGION']
            self.use_ssl = cfg['SSL']
        elif (self.type == "FS"):
            self.islocal_store = True 
        else:
            raise InvalidStore(self.type)

    def islocal(self):
        return self.islocal_store

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
#
class edgex_access:
    def __init__(self):
        # self.pid
        self.max_tasks = 8
        self.valid_taskids = random.sample(range(1,100), self.max_tasks)
        self.used_taskids = []

        max_workers = self.max_tasks
        self.texe = concurrent.futures.ThreadPoolExecutor(max_workers)
        self.jobs = []
        self.taskq = Queue()
        self.resultq = Queue()

        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_access')

    # keep track of the config used to start this process
    def add_config(self, edgex_cfg):
        self.cfg = edgex_cfg

    def get_task_id(self):
        if (len(self.used_taskids) == self.max_tasks):
            return -1
        candidate_list = [x for x in self.valid_taskids if x not in self.used_taskids]
        if (len(candidate_list) == 0):
            return -1
        num = random.choice(candidate_list)
        return num

    def put_task_id(self, taskid):
        if taskid not in self.used_taskids:
            return False
        self.used_tasks.remove(taskid)
        return True

    def submit_task(self, task, cb):
        job = self.texe.submit(task.execute, task.obj_arg)
        job.arg = task.obj_arg
        task.done_callback(cb)
        job.add_done_callback(task.complete)
        self.jobs.append(job)

    def check_jobs(self):
        self.logger.debug("process: job check")
        for fjs in concurrent.futures.as_completed(self.jobs):
            mobj = fjs.arg
            if fjs.cancelled():
                self.logger.debug("Cancelled: " + mobj.pathname())
            elif fjs.done():
                try:
                    error = fjs.exception()
                    if error:
                        self.logger.error("Unexpected Error: " + mobj.pathname() + " Error : " + str(error))
                except Exception as exc:
                    self.logger.error("Unexpected Error: " + str(sys.exc_info()[0]) + "\t" + str(sys.exc_info()[1]))
                    self.logger.error("Exception : " + str(exc.__class__) + "\t" + str(exc.__doc__))
            self.jobs.remove(fjs)
        return len(self.jobs)

    def wait_tasks(self, timeout):
        finished, pending = concurrent.futures.wait(self.jobs, timeout=timeout, return_when=concurrent.futures.ALL_COMPLETED)
        return len(pending)

    def shutdown(self):
        self.logger.debug("shutdown job count : " + str(len(self.jobs)))
        for fjs in self.jobs:
            mobj = fjs.arg
            if fjs.running():
                self.logger.error("shutdown cancel : " + mobj.pathname())
                fjs.cancel()
            elif fjs.done():
                self.logger.debug("shutdown done : " + mobj.pathname())
        self.texe.shutdown(wait=True)
        self.logger.debug("shutdown done")

    def loop(self):
        retry = 0
        while True:
            # TODO: which one or both ? 
            with self.texe as executor:
                retry = self.check_jobs()
            retry = self.wait_tasks(1)
            if (retry == 0):
                break
            self.logger.debug("Pending tasks: " + str(retry))
        self.shutdown()
# ===========================================================================
# edgex_object
# 
class edgex_object:
    def __init__(self, cfg, name, store=None, as_is=False):
        self.oname = name
        # time for the creation of this in-memory object
        t = datetime.utcnow()
        self.amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
        # contains the databuffer on one task only. .. not the entire content-length. 
        self.databuf = None
        # used only to pass around in callbacks etc
        self.arg = None
        self.ctx = None
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_obj')

        if (self.in_memory(cfg, name) is True):
            return

        if (self.localpath(cfg, name, as_is) is True):
            return

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
                    raise InvalidStore("Store not defined: " + sname[0])
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
                    raise InvalidStore("Store not defined: " + str(sname[0]))
                else:
                    is_store=True

            if (sname[0].startswith('//')):
                bpath = re.sub('//', '/',sname[0])
            else:
                bpath = self.oname
        else:
            raise InvalidStore("Store not defined: " + sname[0])
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
                if (not self.oname.endswith("/")):
                    self.oname += "/"
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
            raise InvalidStore(name + ": Store not found")

        if len(self.bucket_name) == 0:
            self.logger.debug("No Bucket name")

        self.logger.info("OBJECT : " + self.pathname())

    # checks in initialization
    def in_memory(self, cfg, name):
        if (name  == "0xdeadbeef"):
            self.obj_name = name
            self.bucket_name = "0xdeadbeef"
            self.store = cfg.get_local_pwd()
            self.isfolder = False
            return True
        else:
            return False

    def localpath(self, cfg, name, as_is):
        if (as_is is True):
            #self.obj_name = os.path.abspath(name)
            self.obj_name = name
            self.bucket_name = os.getcwd()
            self.store = cfg.get_local_pwd()
            self.isfolder = True if os.path.isdir(name) else False
            return True
        else:
            return False

    # Properties of the object
    # 
    def get_store(self):
        return self.store
    def store_type(self):
        return self.store.type
    def islocal(self):
        if (self.store.type == "FS"):
            return True
        else:
            return False
    def bucketname(self):
        return self.bucket_name
    def objname(self):
        return self.obj_name

    # return only the storename://bucketname of this object
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
            fpath = self.bucket_name + "/" + self.obj_name
        elif (self.store_type() == "S3"):
            fpath = self.store.endpoint + "/" + self.bucket_name + "/" + self.obj_name
        else:
            self.logger.error("Error: store_type: " + self.store_type())
            raise InvalidStore(str(sef.store_type()))
        return fpath

    # security  needed to access the object 
    #
    def auth(self):
        auth = AWS4Auth(self.store.access, self.store.secret, self.store.region, 's3')
        return auth
# ============================================================================
#
#
valid_tasks = [ "list", "get", "put", "info", "exists", "delete", "execute" , "terminate" ]
class edgex_task:
    taskid = 0
    taskname = ""
    taskstate = None
    process = None
    obj_arg = None

    @classmethod
    def __init__(cls, process, taskname):
        found = False
        for op in valid_tasks:
            if (taskname.lower() == op.lower()):
                found = True
        if not found:
            raise InvalidCommand(taskname)
        cls.process = process
        cls.taskid = process.get_task_id()
        cls.taskname = taskname
        cls.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_task:' + cls.taskname)
        cls.logger.debug("task " + cls.taskname + " : " + str(cls.taskid) + " init")
        cls.taskstate = "init"

    @classmethod
    def done_callback(cls, cb):
        cls.cb = cb

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.debug("task " + cls.taskname + " : " + str(cls.taskid) + " completed")
        cls.process.put_task_id(cls.taskid)
        cls.taskstate = "done"
        return cls.cb(ret_obj)

    @classmethod
    def execute(cls, obj):
        cls.logger.debug("task " + cls.taskname + " execute")
        cls.taskstate = "exec"
    
class edgex_terminate(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "terminate")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec terminate " + obj.pathname())
        if obj.databuf:
            time.sleep(obj.databuf)
        return obj.databuf

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete terminate")
        return super().complete(ret_obj)



class edgex_list(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "list")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec list: " + obj.pathname())
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
                        cls.logger.error("Unable to parse:")
                        cls.logger.error(response.text)
                        cls.logger.error(objname + "\t\t" + response.headers['Content-Length'] + "\t\t" + response.headers['Last-Modified'])
                except requests.exceptions.RequestException as e:
                    cls.logger.error(str(e))
                    raise e
                except Exception as e:
                    cls.logger.error(str(e))
                    raise e
            return final_list
        else:
            raise InvalidStore(obj.store_type())

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete list")
        return super().complete(ret_obj)

class edgex_info(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "info")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        if (obj.store.type == "FS"):
            metadata = { obj.pathname():os.stat(obj.pathname()) }
            return metadata
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.head(url, auth=obj.auth(), verify=False)
                if (response.status_code != 200) or (not response.ok):
                    cls.logger.error("HEAD " + url + " " + str(response.status_code))
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                else:
                    cls.logger.debug("HEAD " + url + " " + str(response.status_code))
                    return response.headers
            except requests.exceptions.RequestException as e:
                cls.logger.error(str(e))
                raise e
            except Exception as e:
                cls.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete info")
        return super().complete(ret_obj)


class edgex_exists(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "exists")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec exists")
        if (obj.store.type == "FS"):
            return os.path.exists(obj.pathname())
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.head(url, auth=obj.auth(), verify=False)
                if response.status_code != 200 or (not response.ok):
                    cls.logger.error("HEAD " + url + " " + str(response.status_code))
                    cls.logger.error(response.text)
                    #s3err = edgex_s3error(response) 
                    #self.logger.error(s3err.error_text())
                    return False
                else:
                    cls.logger.debug("HEAD " + url + " " + str(response.status_code))
                    return True
            except requests.exceptions.RequestException as e:
                cls.logger.error(str(e))
            except Exception as e:
                cls.logger.error(str(e))
            return False
        else:
            raise InvalidStore(obj.store_type())

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete exists")
        return super().complete(ret_obj)

# TODO: return True or False
class edgex_delete(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "delete")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec delete " + obj.pathname())
        if (obj.store.type == "FS"):
            if os.path.isfile(obj.pathname()):
                os.remove(obj.pathname())
                return True
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
                        cls.logger.debug("DELETE " + url + " " + str(response.status_code))
                        return True
                    else:
                        cls.logger.error("DELETE " + url + " " + str(response.status_code))
                        raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                else:
                    cls.logger.error("DELETE " + url + " " + str(response.status_code))
                    s3err = edgex_s3error(response) 
                    if s3err.error_code() == 'NoSuchKey':
                        return False
                    else:
                        cls.logger.error(s3err.error_text())
                        raise requests.HTTPError(response.text)
            except requests.exceptions.RequestException as e:
                cls.logger.error(str(e))
                raise e
            except Exception as e:
                cls.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete delete")
        return super().complete(ret_obj)


class edgex_get(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "get")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec get " + obj.pathname())
        if (obj.store.type == "FS"):
            file_size = os.stat(obj.pathname()).st_size
            if (file_size > MAX_SINGLE_OBJ):
                cls.logger.error('MaxObjectSize', objtype)
                raise
            file_data = io.open(obj.pathname(), mode='rb')
            fdata_now = file_data.read(file_size)
            return fdata_now
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            try:
                response =  requests.get(url, auth=obj.auth(), verify=False)
                if (response.status_code != 200) or (not response.ok):
                    cls.logger.error("GET " + url + " " + str(response.status_code))
                    s3err = edgex_s3error(response) 
                    cls.logger.error(s3err.error_text())
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                elif (response.status_code == 200) and (response.ok):
                    cls.logger.debug("GET " + url + " " + str(response.status_code))
                    return response.content
                else:
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
            except requests.exceptions.RequestException as e:
                cls.logger.error(str(e))
                raise e
            except Exception as e:
                cls.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete get")
        return super().complete(ret_obj)


class edgex_put(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "put")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec put " + obj.pathname())
        if (obj.store.type == "FS"):
            if not os.path.exists(os.path.dirname(obj.pathname())):
                try:
                    os.makedirs(os.path.dirname(obj.pathname()))
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            open(obj.pathname(), 'wb').write(obj.databuf)
            return
        elif (obj.store.type == "S3"):
            url = obj.store.endpoint + "/" + obj.bucket_name + "/" + obj.obj_name
            databuf_size = len(obj.databuf)
            metaonheader = {}
            metaonheader['Content-Type'] = 'application/octet-stream'
            headers = {
                'Content-Length': str(databuf_size),
            }
            headers.update(metaonheader)
            sha256_hex = edgex_hasher.sha256(obj.databuf).hexdigest()
            try:
                response = requests.put(url, data=obj.databuf, headers=headers, auth=obj.auth(), verify=False)
                if response.status_code == 200:
                    if response.ok:
                        cls.logger.debug("PUT " + url + " " + str(response.status_code))
                        return
                    else:
                        cls.logger.error("PUT " + url + " " + str(response.status_code))
                        raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
                else:
                    s3err = edgex_s3error(response) 
                    cls.logger.error(s3err.error_text())
                    raise HTTPErrorCode(str(response.status_code) + " : " + str(response.text))
            except requests.exceptions.RequestException as e:
                cls.logger.error(str(e))
                raise e
            except Exception as e:
                cls.logger.error(str(e))
                raise e
        else:
            raise InvalidStore(obj.store_type())

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.debug("complete put")
        return super().complete(ret_obj)

class edgex_execute(edgex_task):

    def __init__(cls, process, obj):
        edgex_task(process, "execute")
        cls.obj_arg = obj

    @classmethod
    def execute(cls, obj):
        super().execute(obj)
        cls.logger.info("exec execute " + obj.pathname())
        return "NO_FUNC_IN_OBJ"

    @classmethod
    def complete(cls, ret_obj):
        cls.logger.info("complete execute")
        return super().complete(ret_obj)


if __name__ == "__main__":
    pass
