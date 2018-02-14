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

# Added because some sites do not need ssl certification and that generates 
# warnings in the code.  Disable these warnings for now

from requests.packages.urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)    

from time import mktime, strptime
from datetime import datetime, timedelta
from requests_aws4auth import AWS4Auth

from lxml import etree
from io import StringIO, BytesIO

# internal globals
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB
DEFAULT_ENDPOINT="edge.nexenta.com"
DEFAULT_REGION="us-west-1"
EDGEX_ACCESS_LOG_NAME="edgex_access"

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

def get_sha256_hexdigest(content):
    return edgex_hasher.sha256(content).hexdigest()

def get_md5_base64digest(content):
    return edgex_hasher.md5(content).base64digest()

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
    def enable(self, loglevel):
        logging.enable(loglevel)
    def disable(self, loglevel):
        logging.disable(loglevel)
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
class InvalidXML(edgex_error):
    pass

edgex_error_codes = {
        'AccessDenied': { 'class' : AccessDenied, 'message' : "Access is denied " },
        'InvalidURI': { 'class' : InvalidURI, 'message' : "URI is invalid " },
        'Redirect': { 'class' : Redirect, 'message' : "Temporary Redirect " },
        'ServiceError' : { 'class' : ServiceError, 'message' : "Service Configuration Error " },
        'CommandError' : { 'class' : CommandError, 'message' : "Command Configuration Error " },
        'InvalidObject' : { 'class' : InvalidObject, 'message' : "Object is invalid " },
        'InvalidXML' : { 'class' : InvalidXML, 'message' : "XML is invalid " }
    }

def error_raise(ecode, emsg):
    raise(edgex_error_codes[ecode]['class'](edgex_error_codes[ecode]['message']))

ETREE_EXCEPTIONS = (SyntaxError, AttributeError, ValueError, TypeError)
S3_NS = {'s3' : 'http://s3.amazonaws.com/doc/2006-03-01/'}

class s3error(object):
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

class s3list_parser(object):
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
                print(action + " : " + eltags[1] + " = " + elem.text)
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

class s3parser(object):
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
            s3parser(self.root_name, elem)
            for elem in self.element.findall('s3:{}'.format(name), S3_NS)
        ]
    def find(self, name):
        elt = self.element.find('s3:{}'.format(name), S3_NS)
        return s3parser(self.root_name, elt) if elt is not None else None
    def get_child_text(self, name, strict=True):
        if strict:
            try:
                return self.element.find('s3:{}'.format(name), S3_NS).text
            except ETREE_EXCEPTIONS as error:
                error_print(InvalidXML, 'Invalid XML --')
        else:
            return self.element.findtext('s3:{}'.format(name), None, S3_NS)


class edgex_config:
    def __init__(self):
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_config')
    def load_file(self, fileName):
        self.configured = False
        try:
            dff = open(fileName)
            self.cfg_data = json.load(dff)
            self.configured = True
            self.logger.info(fileName + " loaded")
        except FileNotFoundError:
            self.logger.error("File not found : " + fileName)
            raise
        except json.decoder.JSONDecodeError:
            self.logger.error("JSON format error ")
        except:
            self.logger.error("Unexpected Error: ", sys.exc_info()[0])
            raise
        self.logger.info("configuration  loaded")
    @classmethod
    def fromstring(self, config_str):
        self.configured = False
        try:
            self.cfg_data = json.loads(config_str)
            self.configured = True
        except json.decoder.JSONDecodeError:
            self.logger.error("JSON format error ")
        except:
            self.logger.error("Unexpected Error: ", sys.exc_info()[0])
            raise
        self.logger.info("configuration  loaded")
    def save_file(self, fileName):
        try:
            jsondata = simplejson.dumps(self.cfg_data, indent=4, skipkeys=True, sort_keys=True)
            fd = open(fileName, 'w')
            fd.write(jsondata)
            fd.close()
            self.logger.info("File " + fileName + " saved")
        except:
            self.logger.error("ERROR writing " +  fileName)
            pass
    def configure(self, service_name, params):
        if self.configured:
            self.cfg_data[service_name]['ACCESS'] = params[0]
            self.cfg_data[service_name]['SECRET'] = params[1]
            self.cfg_data[service_name]['REGION'] = params[2]
            self.cfg_data[service_name]['ENDPOINT'] = params[3]
            self.cfg_data[service_name]['TESTBUCKET'] = params[4]
        else:
            self.cfg_data[service_name] \
                    = { 'ACCESS' : params[0], \
                        'SECRET' : params[1], \
                        'REGION' : params[2], \
                        'ENDPOINT' : params[3], \
                        'TESTBUCKET' : params[4] }
    def getcfg(self):
        return self.cfg_data
    def saveCfg(self, fileName):
        return self.save_file(fileName)
    def get(self, store_name):
        return self.cfg_data[store_name]
    def getPrimaryService(self):
        self.service_name = self.cfg_data['PRIMARY']
        return self.service_name
    def setPrimaryService(self, pname, fileName):
        self.service_name = pname
        self.saveCfg(fileName)
    def getEndpoint(self):
        return self.cfg_data[self.service_name]['ENDPOINT']
    def getRegion(self):
        return self.cfg_data[self.service_name]['REGION']
    def getSecretKey(self):
        return self.cfg_data[self.service_name]['SECRET']
    def getAccessKey(self):
        return self.cfg_data[self.service_name]['ACCESS']
    def getTestBucket(self):
        return self.cfg_data[self.service_name]['DEFAULT_BUCKET']
    def current(self):
        return self.cfg_data[self.service_name]

class edgex_store_access():
    def __init__(self, edgex_cfg):
        self.access = edgex_cfg.getAccessKey()
        self.secret = edgex_cfg.getSecretKey()
        self.service_name = edgex_cfg.getPrimaryService()
        self.region = edgex_cfg.getRegion()
        self.endpoint = edgex_cfg.getEndpoint()
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_store_access')
        self.edgex_cfg = edgex_cfg
    def list_buckets(self, recursive):
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        try:
            response = requests.get(self.endpoint, auth=auth, verify=False)
            if response.status_code == 200:
                self.logger.debug("GET " + self.endpoint + " " + str(response.status_code))
                if (response.text.startswith("<!doctype html>") == True):
                    self.logger.error("Illegal HTML response on a GET: ") 
                    raise
                eroot = s3list_parser(response.text)
                top_name = eroot.find_element_one('ListAllMyBucketsResult/Owner/DisplayName')
                blist = eroot.find_element_list('ListAllMyBucketsResult/Buckets/Bucket', 'Name')
                print(top_name)
                for bucket in blist:
                    print("\t" + bucket)
            else:
                self.logger.error("GET " + self.endpoint + " " + str(response.status_code))
                s3err = s3error(response) 
                self.logger.error(s3err.error_text())
        except requests.exceptions.RequestException as e:
            print(str(e))
            self.logger.error(str(e))
            return
    def list(self, bucketName, objname, recursive=False):
        edgex_obj = edgex_obj_access(self.edgex_cfg)
        if not recursive:
            objs = edgex_obj.list_obj(bucketName + "/" + objname)
            for item in objs:
                print(item)
        else:
            objs = edgex_obj.list_obj(bucketName + "/" + objname)
            for item in objs:
                if item.endswith("/"):
                    print("\t" + item)
                    self.list(bucketName, item, recursive)
                else:
                    print("\t\t"+ item)

class edgex_obj_access():
    def __init__(self, edgex_cfg):
        if not self.validate_region(edgex_cfg.getRegion, edgex_cfg.getEndpoint):
            self.region = DEFAULT_REGION
            self.endpoint = DEFAULT_ENDPOINT
        if not edgex_cfg.getAccessKey() or not edgex_cfg.getSecretKey():
            raise ServiceError("ACCESS/SECRET/REGION not specified correctly")
        self.access = edgex_cfg.getAccessKey()
        self.secret = edgex_cfg.getSecretKey()
        self.service_name = edgex_cfg.getPrimaryService()
        self.region = edgex_cfg.getRegion()
        self.endpoint = edgex_cfg.getEndpoint()
        self.testbucket = edgex_cfg.getTestBucket()
        self.logger = logging.getLogger(EDGEX_ACCESS_LOG_NAME + '.edgex_obj_access')
    def validate_region(self, region, endpoint):
        if not region or not endpoint:
            self.logger.error("Invalid region : " + region + \
                    " Invalid endpoint: " + endpoint)
            return False
    def check_bucket(self, bucket):
        return True
    def check_objpath(self, objpath):
        return True
    def info_access(self):
        print("Service: " + self.service_name)
        print("ACCESS: " + self.access)
        print("SECRET: " + self.secret)
        print("REGION: " + self.region)
        print("ENDPOINT: " + self.endpoint)
        print("TESTBUCKET: " + self.testbucket)

    def test_one_obj(self, objname):
        if not objname:
            objfile = "ofile1"
            if os.path.exists(objfile):
                os.remove(objfile)
            with open(objfile, 'wb') as fout:
                fout.write(os.urandom(1024))
        else:
            objfile = objname
        try:
            fl = open(objfile)
        except FileNotFoundError:
            self.logger.error("Need a file to upload")
            return
        objname = self.testbucket + "/" + objfile
        f = self.exists_obj(objname)
        self.logger.info("Exists?: " + objname + " : " + str(f))
        if f:
            ff = self.remove_obj(objname)
            self.logger.info("Remove?: " + objname + " : " + str(ff))
        pf = self.put_obj(objname, fileName=objfile)
        self.logger.info("Put?: " + objname + " : " + str(pf))
        if pf:
            f = self.exists_obj(objname)
            self.logger.info("Exists?: " + objname + " : " + str(f))
        else:
            return
        localFile = objfile + "--"
        if os.path.exists(localFile):
            os.remove(localFile)
        f = self.get_obj(objname, fileName=localFile)
        self.logger.info("Get?: " + objname + " : " + str(f))
        if f:
            ff = self.remove_obj(objname)
            self.logger.info("Remove?: " + objname + " : " + str(ff))
    def exists_obj(self, objname, header_options=None):
        objp = objname.split("/")
        bucketName = objp[0]
        objpath = "/".join(objp[1:])
        if not self.check_bucket(bucketName) or not self.check_objpath(objpath):
            self.logger.error('InvalidObject', objname)
            return
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        url = self.endpoint + "/" + bucketName + "/" + objpath
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
                #s3err = s3error(response) 
                #self.logger.error(s3err.error_text())
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
        return False
    def get_obj(self, objname, fileName=None, header_options=None):
        objp = objname.split("/")
        bucketName = objp[0]
        objpath = "/".join(objp[1:])
        if not self.check_bucket(bucketName) or not self.check_objpath(objpath):
            self.logger.error('InvalidObject', objname)
            return
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        url = self.endpoint + "/" + bucketName + "/" + objpath
        try:
            response =  requests.get(url, auth=auth, verify=False)
            if response.status_code == 200:
                if response.ok and fileName:
                    self.logger.debug("GET " + url + " " + str(response.status_code))
                    open(fileName, 'wb').write(response.content)
                    return True
                else:
                    self.logger.error("GET " + url + " " + str(response.status_code))
                    self.logger.error("File: " + fileName)
                    return False
            else:
                s3err = s3error(response) 
                self.logger.error(s3err.error_text())
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
        return False

    def put_obj(self, objname, fileName=None, header_options=None):
        objp = objname.split("/")
        bucketName = objp[0]
        objpath = "/".join(objp[1:])
        if not self.check_bucket(bucketName) or not self.check_objpath(objpath):
            self.logger.error('InvalidObject', objname)
            return
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        url = self.endpoint + "/" + bucketName + "/" + objpath
        file_data = io.open(fileName, mode='rb')
        file_size = os.stat(fileName).st_size
        metaonheader = {}
        metaonheader['Content-Type'] = 'application/octet-stream'
        if file_size > MIN_PART_SIZE:
            self.logger.error("Too big for a single put")
            return False
        fdata_now = file_data.read(file_size)
        headers = {
            'Content-Length': str(file_size),
        }
        headers.update(metaonheader)
        sha256_hex = edgex_hasher.sha256(fdata_now).hexdigest()
        try:
            response = requests.put(url, data=fdata_now, headers=headers, auth=auth, verify=False)
            if response.status_code == 200:
                if response.ok:
                    self.logger.debug("PUT " + url + " " + str(response.status_code))
                    return True
                else:
                    self.logger.error("PUT " + url + " " + str(response.status_code))
                    return False
            else:
                s3err = s3error(response) 
                self.logger.error(s3err.error_text())
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
        return False
    def multipart_put(self, objname, header_options=None):
        print("multipart put not done")
    def remove_obj(self, objname, header_options=None):
        objp = objname.split("/")
        bucketName = objp[0]
        objpath = "/".join(objp[1:])
        if not self.check_bucket(bucketName) or not self.check_objpath(objpath):
            self.logger.error('InvalidObject', objname)
            return
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        url = self.endpoint + "/" + bucketName + "/" + objpath
        try:
            response =  requests.delete(url, auth=auth, verify=False)
            if response.status_code == 200 or response.status_code == 204:
                if response.ok:
                    self.logger.debug("DELETE " + url + " " + str(response.status_code))
                    return True
                else:
                    self.logger.error("DELETE " + url + " " + str(response.status_code))
                    return False
            else:
                self.logger.error("DELETE " + url + " " + str(response.status_code))
                s3err = s3error(response) 
                if s3err.error_code() == 'NoSuchKey':
                    return True
                else:
                    self.logger.error(s3err.error_text())
                    return False
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
        return False

    def info_obj(self, objname, header_options=None):
        objp = objname.split("/")
        bucketName = objp[0]
        objpath = "/".join(objp[1:])
        if not self.check_bucket(bucketName) or not self.check_objpath(objpath):
            self.logger.error('InvalidObject', objname)
            return
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        url = self.endpoint + "/" + bucketName + "/" + objpath
        try:
            response =  requests.head(url, auth=auth, verify=False)
            if response.status_code == 200:
                if response.ok:
                    self.logger.debug("HEAD " + url + " " + str(response.status_code))
                    return response.headers
                else:
                    self.logger.error("HEAD " + url + " " + str(response.status_code))
                    return None
            else:
                return None
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
        return None
    def list_obj(self, dname, header_options=None):
        objp = dname.split("/")
        bucketName = objp[0]
        objpath = "/".join(objp[1:])
        if not self.check_bucket(bucketName) or not self.check_objpath(objpath):
            self.logger.error('InvalidObject', objname)
            return
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        url = self.endpoint + "/" + bucketName + "/" + "?list-type=2&prefix=" + objpath + "&delimiter=/"
        final_list = []
        try:
            response =  requests.get(url, auth=auth, verify=False)
            if response.status_code == 200:
                if response.ok:
                    if response.headers['Content-Type'] == 'application/xml':
                        eroot = s3list_parser(response.text)
                        top_name = eroot.find_element_one('ListBucketsResult/Name')
                        contents = eroot.find_element_list('ListBucketsResult/Contents', 'Key')
                        subdir = eroot.find_element_list_key('ListBucketsResult/CommonPrefixes','Prefix')
                        for content in contents:
                            final_list.append(content)
                        for mdir in subdir:
                            final_list.append(mdir)
                        return final_list
                    else:
                        print(objname + "\t\t" + response.headers['Content-Length'] + "\t\t" + response.headers['Last-Modified'])
                else:
                    self.logger.error("HEAD " + url + " " + str(response.status_code))
            else:
                self.logger.error("Error: " + str(response.status_code))
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
    def put_obj_recursive(self, objname, dname, header_options=None):
        for path, dirnames, filenames in os.walk(dname):
            for fname in filenames:
                fln=os.path.join(path, fname)
                oname = objname + "/" + fln
                self.put_obj(oname, fileName=fln)
    def get_obj_recursive(self, tdname, dname, header_options=None):
        ls = self.list_obj(tdname)
        objp = tdname.split("/")
        bucketName = objp[0]
        dirName = objp[1:]
        ls = self.list_obj(tdname)
        for item in ls:
            remoteObj = bucketName + "/" + item
            self.logger.debug(item)
            if item.endswith("/"):
                localDir = dname + "/" + item
                try:
                    os.stat(localDir)
                except:
                    if not os.path.exists(localDir):
                        os.makedirs(localDir)
                self.get_obj_recursive(bucketName + "/" + item, dname)
            else:
                localFile = dname + "/" + item
                self.get_obj(remoteObj, localFile)
    def remove_obj_recursive(self, dname, header_options=None):
        objp = dname.split("/")
        bucketName = objp[0]
        dirName = objp[1:]
        ls = self.list_obj(dname)
        for item in ls:
            self.logger.debug(item)
            if item.endswith("/"):
                if (len(ls) > 0):
                    self.remove_obj_recursive(bucketName + "/" + item)
                    self.remove_obj(bucketName + "/" + item)
                else:
                    self.remove_obj(bucketName + "/" + item)

            else:
                self.remove_obj(bucketName + "/" + item)

if __name__ == "__main__":
    pass
