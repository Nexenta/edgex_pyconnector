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

# added because some sites do not need ssl certification 
# and that generates warnings in the code
# disable these warnings for now
from requests.packages.urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)    

from time import mktime, strptime
from datetime import datetime, timedelta
from requests_aws4auth import AWS4Auth

from s3parser import (s3parser, s3error, s3list_parser)
from edgeerror import (edge_error, InvalidXML, AccessDenied, InvalidURI, \
                        Redirect, ServiceError, CommandError, InvalidObject, \
                        error_raise)
from sigmisc import Hasher

# create logger
import logging
EDGE_ACCESS_LOG_NAME="edge_access"
module_logger = logging.getLogger(EDGE_ACCESS_LOG_NAME)
from edge_logger import edge_logger

# TODO:
# can we move all global #define to a file ? 
#
MIN_PART_SIZE = 5 * 1024 * 1024  # 5MiB
default_endpoint="edge.nexenta.com"
default_region="us-west-1"

EDGE_CONFIG_FILE=1
EDGE_CONFIG_JSON=2

class edge_config:
    def __init__(self):
        self.logger = logging.getLogger(EDGE_ACCESS_LOG_NAME + '.edge_config')
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
        except:
            #print("ERROR writing " +  fileName + " " + str(sys.exc_info()[0]))
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

class edge_store_access():
    def __init__(self, edge_cfg):
        self.access = edge_cfg.getAccessKey()
        self.secret = edge_cfg.getSecretKey()
        self.service_name = edge_cfg.getPrimaryService()
        self.region = edge_cfg.getRegion()
        self.endpoint = edge_cfg.getEndpoint()
        self.logger = logging.getLogger(EDGE_ACCESS_LOG_NAME + '.edge_store_access')
        self.edge_cfg = edge_cfg
    def list_buckets(self, recursive):
        auth = AWS4Auth(self.access, self.secret, self.region, 's3')
        try:
            response = requests.get(self.endpoint, auth=auth, verify=False)
            if response.status_code == 200:
                self.logger.debug("GET " + self.endpoint + " " + str(response.status_code))
                # TODO
                #if (response.text.startwith("<!doctype html>") == True):
                #    raise
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
        edge_obj = edge_obj_access(self.edge_cfg)
        if not recursive:
            objs = edge_obj.list_obj(bucketName + "/" + objname)
            for item in objs:
                print(item)
        else:
            objs = edge_obj.list_obj(bucketName + "/" + objname)
            for item in objs:
                if item.endswith("/"):
                    print("\t" + item)
                    self.list(bucketName, item, recursive)
                else:
                    print("\t\t"+ item)

class edge_obj_access():
    def __init__(self, edge_cfg):
        if not self.validate_region(edge_cfg.getRegion, edge_cfg.getEndpoint):
            self.region = default_region
            self.endpoint = default_endpoint
        if not edge_cfg.getAccessKey() or not edge_cfg.getSecretKey():
            raise ServiceError("ACCESS/SECRET/REGION not specified correctly")
        self.access = edge_cfg.getAccessKey()
        self.secret = edge_cfg.getSecretKey()
        self.service_name = edge_cfg.getPrimaryService()
        self.region = edge_cfg.getRegion()
        self.endpoint = edge_cfg.getEndpoint()
        self.testbucket = edge_cfg.getTestBucket()
        self.logger = logging.getLogger(EDGE_ACCESS_LOG_NAME + '.edge_obj_access')
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
                    self.logger.error("HEAD " + url + " " + str(response.status_code))
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
        sha256_hex = Hasher.sha256(fdata_now).hexdigest()
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
        print("multipart put")
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
                    print("HEAD " + url + " " + str(response.status_code))
            else:
                print("Error: " + str(response.status_code))
        except requests.exceptions.RequestException as e:
            self.logger.error(str(e))
        except Exception as e:
            self.logger.error(str(e))
    def put_obj_recursive(self, objname, dname, header_options=None):
        print("objname: " + objname + " dname: " + dname)
        for path, dirnames, filenames in os.walk(dname):
            for fname in filenames:
                fln=os.path.join(path, fname)
                oname = objname + "/" + fln
                print("remote object: " + oname + " file: " + fln)
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

