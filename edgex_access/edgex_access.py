import json
import os
import time
import re
import asyncio 
import async_timeout

import aiohttp
import aiofiles
import aiodns
import aiobotocore 

import sys
import logging

from time import mktime, strptime
from datetime import datetime, timedelta

ACCESS_LOG_NAME="edgex_access"
MAX_SINGLE_OBJ=5* 1024 * 1024 * 1024 # 5Gb


from xml.etree.ElementTree import fromstring as parse_xml, ParseError

# Error objects, Exceptions etc 
# ============================================================================

class edgex_s3exception(Exception):
    """Base for exceptions returned by S3 servers"""

    @staticmethod
    def from_bytes(status, body):
        if not body:
            raise RuntimeError("HTTP Error {}".format(status))
        try:
            xml = parse_xml(body)
        except ParseError:
            raise RuntimeError(body)
        code_el = xml.find("Code")
        if code_el is None or not code_el.text:
            raise RuntimeError(body)
        class_name = code_el.text
        try:
            cls = globals()[class_name]
        except KeyError:
            raise RuntimeError("Error {} is unknown".format(class_name))
        msg = xml.find("Message")
        return cls(class_name if msg is None else msg.text)


class AccessDenied(edgex_s3exception): pass
class AccountProblem(edgex_s3exception): pass
class AmbiguousGrantByEmailAddress(edgex_s3exception): pass
class BadDigest(edgex_s3exception): pass
class BucketAlreadyExists(edgex_s3exception): pass
class BucketAlreadyOwnedByYou(edgex_s3exception): pass
class BucketNotEmpty(edgex_s3exception): pass
class CredentialsNotSupported(edgex_s3exception): pass
class CrossLocationLoggingProhibited(edgex_s3exception): pass
class EntityTooSmall(edgex_s3exception): pass
class EntityTooLarge(edgex_s3exception): pass
class ExpiredToken(edgex_s3exception): pass
class IllegalVersioningConfigurationException(edgex_s3exception): pass
class IncompleteBody(edgex_s3exception): pass
class IncorrectNumberOfFilesInPostRequest(edgex_s3exception): pass
class InlineDataTooLarge(edgex_s3exception): pass
class InternalError(edgex_s3exception): pass
class InvalidAccessKeyId(edgex_s3exception): pass
class InvalidAddressingHeader(edgex_s3exception): pass
class InvalidArgument(edgex_s3exception): pass
class InvalidBucketName(edgex_s3exception): pass
class InvalidBucketState(edgex_s3exception): pass
class InvalidDigest(edgex_s3exception): pass
class InvalidEncryptionAlgorithmError(edgex_s3exception): pass
class InvalidLocationConstraint(edgex_s3exception): pass
class InvalidObjectState(edgex_s3exception): pass
class InvalidPart(edgex_s3exception): pass
class InvalidPartOrder(edgex_s3exception): pass
class InvalidPayer(edgex_s3exception): pass
class InvalidPolicyDocument(edgex_s3exception): pass
class InvalidRange(edgex_s3exception): pass
class InvalidRequest(edgex_s3exception): pass
class InvalidSecurity(edgex_s3exception): pass
class InvalidSOAPRequest(edgex_s3exception): pass
class InvalidStorageClass(edgex_s3exception): pass
class InvalidTargetBucketForLogging(edgex_s3exception): pass
class InvalidToken(edgex_s3exception): pass
class InvalidURI(edgex_s3exception): pass
class InvalidCommand(edgex_s3exception): pass
class InvalidStore(edgex_s3exception): pass
class KeyTooLong(edgex_s3exception): pass
class MalformedACLError(edgex_s3exception): pass
class MalformedPOSTRequest(edgex_s3exception): pass
class MalformedXML(edgex_s3exception): pass
class MaxMessageLengthExceeded(edgex_s3exception): pass
class MaxPostPreDataLengthExceededError(edgex_s3exception): pass
class MetadataTooLarge(edgex_s3exception): pass
class MethodNotAllowed(edgex_s3exception): pass
class MissingAttachment(edgex_s3exception): pass
class MissingContentLength(edgex_s3exception): pass
class MissingRequestBodyError(edgex_s3exception): pass
class MissingSecurityElement(edgex_s3exception): pass
class MissingSecurityHeader(edgex_s3exception): pass
class NoLoggingStatusForKey(edgex_s3exception): pass
class NoSuchBucket(edgex_s3exception): pass
class NoSuchKey(edgex_s3exception): pass
class NoSuchLifecycleConfiguration(edgex_s3exception): pass
class NoSuchUpload(edgex_s3exception): pass
class NoSuchVersion(edgex_s3exception): pass
class NotImplemented(edgex_s3exception): pass
class NotSignedUp(edgex_s3exception): pass
class NotSuchBucketPolicy(edgex_s3exception): pass
class OperationAborted(edgex_s3exception): pass
class PermanentRedirect(edgex_s3exception): pass
class PreconditionFailed(edgex_s3exception): pass
class Redirect(edgex_s3exception): pass
class RestoreAlreadyInProgress(edgex_s3exception): pass
class RequestIsNotMultiPartContent(edgex_s3exception): pass
class RequestTimeout(edgex_s3exception): pass
class RequestTimeTooSkewed(edgex_s3exception): pass
class RequestTorrentOfBucketError(edgex_s3exception): pass
class SignatureDoesNotMatch(edgex_s3exception): pass
class ServiceUnavailable(edgex_s3exception): pass
class SlowDown(edgex_s3exception): pass
class TemporaryRedirect(edgex_s3exception): pass
class TokenRefreshRequired(edgex_s3exception): pass
class TooManyBuckets(edgex_s3exception): pass
class UnexpectedContent(edgex_s3exception): pass
class UnresolvableGrantByEmailAddress(edgex_s3exception): pass
class UserKeyMustBeSpecified(edgex_s3exception): pass


# ============================================================================
# Error End


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
    
    def __init__(self, debug_level, logFile):
        if (debug_level >= 3):
            return

        #file_format='[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s'
        #file_format='%(levelname)s:%(message)s'
        file_format='%(levelname)s:{%(filename)s:%(lineno)d}: %(message)s'
        log_level =  logger_level[debug_level]
        logging.basicConfig(format=file_format, level=log_level,
                             filename=logFile,
                             filemode='a')

        h = logging.StreamHandler(sys.stdout)
        h.flush = sys.stdout.flush
        h.setLevel(logging.ERROR)

        self.logger = logging.getLogger(ACCESS_LOG_NAME)

        self.logger.addHandler(h)
       
    def log_print(self, logData):
        print(logData)

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



class edgex_store:
    def __init__(self):
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
    def default_bucket(self):
        return self.bucket

    def list_buckets():
        # TODO
        pass


class edgex_config:
    def __init__(self, cfg_filedata, elog):
        self.cfg_data = json.loads(cfg_filedata) 
        self.store_dict = {}
        stores = self.cfg_data['stores']
        for x in stores:
            self.store_dict[ x['NAME'] ] = edgex_store()
            self.store_dict[ x['NAME'] ].fromjson(x)
        if self.cfg_data['PRIMARY']:
            self.primary = self.cfg_data['PRIMARY']
        if self.cfg_data['DEBUG']:
            self.debug_level = self.cfg_data['DEBUG']
        if self.cfg_data['SYNCIO']:
            self.syncio = self.cfg_data['SYNCIO']
        self.elog = elog

    def get_primary_store(self):
        if (self.cfg_data['PRIMARY'] is None):
            raise
        return self.cfg_data['PRIMARY']

    def show_stores(self):
        for k in self.store_dict:
            store = self.store_dict[k]
            self.elog.log_print(store.name + "\t" + store.get_type() + "\t" + store.default_bucket())

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

    # TODO: revise
    def get_local_pwd(self):
        store = edgex_store()
        store.create("file", "FS", os.getcwd())
        self.store_dict["file"] = store
        return store

    def show_all(self):
        elog.log_print("primary:" + "\t" + self.primary)
        elog.log_print("debug_level: " + "\t" + str(self.debug_level))
        elog.log_print("syncio :" + "\t" + self.syncio)
        elog.log_print("stores:")
        self.show_stores()

class edgex_object:
    def __init__(self, cfg, elog, name, store=None, as_is=False):
        self.oname = name
        self.as_is = as_is
        self.cfg = cfg

        # time for the creation of this in-memory object
        t = datetime.utcnow()
        self.amzdate = t.strftime('%Y%m%dT%H%M%SZ')
        self.datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
        self.elog = elog

        # contains the databuffer on one task only. .. not the entire content-length. 
        self.databuf = None
        self.obj_name = ""
        self.bucket_name = ""

        # used only to pass around in callbacks etc
        self.arg = None
        self.ctx = None

        if (self.localpath() is True):
            return

        if store is None:
            is_store = False
        else:
            is_store = True

        # first we figure out the stores, parse the names etc
        sname = self.oname.split(":")
        if (len(sname) == 2):
            if is_store is False:
                store = self.cfg.get_store(sname[0])
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
                store = self.cfg.get_store(sname[0])
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
            # sometimes isdir does not good enough 
            # so added below
            if self.oname.endswith("/"):
                self.isfolder = True

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

        if (len(self.bucket_name) == 0 and (self.store.get_type() != "FS")):
            self.elog.log_debug("No Bucket name")

        self.elog.log_debug("OBJECT : " + self.pathname())

        if ((self.store is None) and (self.as_is is False)):
            self.store = self.cfg.get_primary_store()
            self.bucket_name = self.store.default_bucket()

        
    def localpath(self):
        if (self.as_is is True):
            self.obj_name = self.oname
            self.bucket_name = os.getcwd()
            self.store = self.cfg.get_local_pwd()
            self.isfolder = True if os.path.isdir(self.oname) else False
            return True
        else:
            return False

    # Properties of the object
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
        if (self.bucket_name == None):
            return None
        else:
            return self.bucket_name
    def objname(self):
        if (self.obj_name == None):
            return None
        else:
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
                self.elog.log_info("mkdir " + self.pathname())
                os.makedirs(self.pathname())
            else:
                return file_found
        else:
            self.elog.log_error("Error: No stat on store_type: " + self.store_type())
            raise InvalidStore(str(sef.store_type()))

    def pathname(self):
        if (self.store_type() == "FS"):
            fpath = self.bucket_name + "/" + self.obj_name
        elif (self.store_type() == "S3"):
            fpath = self.store.endpoint + "/" + self.bucket_name + "/" + self.obj_name
        else:
            self.elog.log_error("Error: store_type: " + self.store_type())
            raise InvalidStore(str(self.store_type()))
        return fpath

    def auth(self):
        auth = AWS4Auth(self.store.access, self.store.secret, self.store.region, 's3')
        return auth

    # return only the name
    def addchild(self, child):
        if (self.store_type() == "FS"):
            objname = "//" + str(self.pathname()) + child
        elif (self.store_type() == "S3"):
            objname = self.basename() + self.objname() + child
        else:
            raise InvalidStore(str(self.store_type()))
        childobj = edgex_object(self.cfg, self.elog, objname, store=self.store)
        return childobj

    def makefolder(self):
        if not self.isfolder and self.oname.endswith("/"):
            self.oname += "/"
            self.isfolder = True

class edgex_access:
    def __init__(self, obj, elog):
        if (obj is None):
            raise InvalidArgument(str(None))
        self.obj = obj
        self.elog = elog

    async def list(self, session):
        if (session is None):
            raise InvalidArgument(str(session))
        self.elog.log_info("list " + self.obj.pathname())
        final_list = []
        if (self.obj.store_type() == "FS"):

            if self.obj.isfolder:
                final_list = os.listdir(self.obj.pathname())
                i=0
                for f in final_list:
                    if os.path.isdir(self.obj.pathname() + "/" + f):
                        final_list[i] = f + "/"
                    i+=1
            else:
                if os.path.isfile(self.obj.pathname()):
                    final_list.append(self.obj.pathname())
            return final_list

        elif (self.obj.store_type() == "S3"):

            async with session.create_client('s3', region_name=self.obj.store.region, \
                                aws_secret_access_key=self.obj.store.secret, \
                                aws_access_key_id=self.obj.store.access, \
                                endpoint_url=self.obj.store.endpoint) as client:

                prefix = self.obj.objname()
                resp = await client.list_objects(Bucket=self.obj.bucketname(), Prefix=prefix, Delimiter='/')
                retcode = resp['ResponseMetadata']['HTTPStatusCode']
                if (retcode != 200):
                    raise

                if 'CommonPrefixes' in resp:
                    for x in resp['CommonPrefixes']:
                        if (prefix.endswith('/') and (len(prefix) > 0) and (prefix != x['Prefix'])):
                            final_list.append(x['Prefix'].replace(prefix,''))
                        elif (len(prefix) == 0):
                            final_list.append(x['Prefix'])
                        else:
                            dlist = x['Prefix'].split('/')
                            if (len(dlist) > 0):
                                if (len(dlist[-1]) > 0):
                                    final_list.append(dlist[-1])
                                elif (len(dlist[-2]) > 0):
                                    final_list.append(dlist[-2])
                            else:
                                final_list.append(x['Prefix'])
                elif 'Contents' in resp:
                    for x in resp['Contents']:
                        if (prefix.endswith('/') and (len(prefix) > 0)):
                            final_list.append(x['Key'].replace(prefix,''))
                        else:
                            dlist = x['Key'].split('/')
                            if (len(dlist) > 0):
                                final_list.append(dlist[-1])
                            else:
                                final_list.append(x['Prefix'])
                return final_list

        else:
            raise InvalidStore(self.obj.store_type())
                    
    async def exists(self, session):
        if (session is None):
            raise InvalidArgument(str(session))
        self.elog.log_info("exists " + self.obj.pathname())
        if (self.obj.store_type() == "FS"):
            if (self.obj.stat() == True):
                return True
            else:
                return False

        elif (self.obj.store_type() == "S3"):
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                        aws_secret_access_key=self.obj.store.secret, \
                                        aws_access_key_id=self.obj.store.access, \
                                        endpoint_url=self.obj.store.endpoint) as client:
                try:
                    hd = await client.head_object(Bucket=self.obj.bucketname(), Key=self.obj.objname())
                    retcode = hd['ResponseMetadata']['HTTPStatusCode']
                    if (retcode == 200):
                        return True
                    else:
                        return False
                except:
                    return False
        else:
            raise InvalidArgument(self.obj.store_type())

    async def delete(self, session):
        if (session is None):
            raise InvalidArgument(str(session))

        self.elog.log_info("delete " + self.obj.pathname())
        if (self.obj.store_type() == "FS"):
            if os.path.isfile(self.obj.pathname()):
                os.remove(self.obj.pathname())
                return True
            if os.path.isdir(self.obj.pathname()):
                dentries = os.listdir(self.obj.pathname())
                if (len(dentries) == 0):
                    os.rmdir(self.obj.pathname())

        elif (self.obj.store_type() == "S3"):
        
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                            aws_secret_access_key=self.obj.store.secret, \
                                            aws_access_key_id=self.obj.store.access, \
                                            endpoint_url=self.obj.store.endpoint) as client:
                try:
                    del_obj = await client.delete_object(Bucket=self.obj.bucketname(), Key=self.obj.objname())
                    retcode = del_obj['ResponseMetadata']['HTTPStatusCode']
                    if ( (retcode == 200) or (retcode == 204) ):
                        return True
                    else:
                        return False
                except:
                    return False
        else:
            raise InvalidArgument(self.obj.store_type())
       
    async def info(self, session):
        if (session is None):
            raise InvalidArgument(str(session))
        self.elog.log_info("info " + self.obj.pathname())
        if (self.obj.store_type() == "FS"):
            if (self.obj.stat() == True):
                metadata = { self.obj.pathname():os.stat(self.obj.pathname()) }
                return metadata
            else:
                return None

        elif (self.obj.store_type() == "S3"):
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                        aws_secret_access_key=self.obj.store.secret, \
                                        aws_access_key_id=self.obj.store.access, \
                                        endpoint_url=self.obj.store.endpoint) as client:
                try:
                    hd = await client.head_object(Bucket=self.obj.bucketname(), Key=self.obj.objname())
                    retcode = hd['ResponseMetadata']['HTTPStatusCode']
                    if (retcode == 200):
                        return hd['ResponseMetadata']['HTTPHeaders']
                    else:
                        return None
                except:
                    return None
        else:
            raise InvalidArgument(self.obj.store_type())

    async def get(self, session):
        if (session is None):
            raise InvalidArgument(str(session))
        self.elog.log_info("get " + self.obj.pathname())

        if (self.obj.store_type() == "FS"):
            file_size = os.stat(self.obj.pathname()).st_size
            if (file_size > MAX_SINGLE_OBJ):
                raise EntityTooLarge(str(file_size))
            async with aiofiles.open(self.obj.pathname(), mode='r', encoding="latin-1") as f:
                file_data = await f.read()
            f.close()
            return file_data

        elif (self.obj.store_type() == "S3"):
            async with session.create_client('s3', region_name=self.obj.store.region, \
                                                aws_secret_access_key=self.obj.store.secret, \
                                                aws_access_key_id=self.obj.store.access, \
                                                endpoint_url=self.obj.store.endpoint) as client:
                try:
                    with async_timeout.timeout(10):
                        gobj = await client.get_object(Bucket=self.obj.bucketname(), Key=self.obj.objname())
                        body = await gobj['Body'].read()
                        gobj['Body'].close()
                        return body
                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    self.elog.log_error("Unexpected Error: " + str(exc_type) + " " + str(fname) + " " + str(exc_tb.tb_lineno))
                    raise e
        else:
            raise InvalidArgument(self.obj.store_type())
                
    async def put(self, session):
        if (session is None):
            raise InvalidArgument(str(session))

        self.elog.log_info("put " + self.obj.pathname())
        if (self.obj.databuf != None):
            isdbuf = True
        else:
            isdbuf = False
        if (self.obj.arg != None):
            isarg = True
        else:
            isarg = False

        self.elog.log_info("put " + self.obj.pathname() + " databuf " + str(isdbuf))
        self.elog.log_info("put " + self.obj.pathname() + " arg " + str(isarg))

        if (isdbuf != True):
            if (self.obj.store_type() == "FS"):
                try:
                    os.makedirs(os.path.dirname(self.obj.pathname()))
                except Exception as e:
                    raise e
                return self.obj.pathname()

            else:
                self.elog.log_error("No databuf : " + self.obj.pathname())
                raise InvalidArgument(str(self.obj.pathname()))

        if (self.obj.store_type() == "FS"):
            if not os.path.exists(os.path.dirname(self.obj.pathname())):
                try:
                    os.makedirs(os.path.dirname(self.obj.pathname()))
                except Exception as e:
                    raise e
                open(self.obj.pathname(), 'wb').write(self.obj.databuf)

            return self.obj.pathname()

        elif (self.obj.store_type() == "S3"):

            async with session.create_client('s3', region_name=self.obj.store.region, \
                                                aws_secret_access_key=self.obj.store.secret, \
                                                aws_access_key_id=self.obj.store.access, \
                                                endpoint_url=self.obj.store.endpoint) as client:
                try:
                    with async_timeout.timeout(10):
                        pobj = await client.put_object(Bucket=self.obj.bucketname(), \
                                                        Key=self.obj.objname(), \
                                                        Body = self.obj.databuf)
                    return self.obj.pathname()

                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    elog.log_error("Unexpected Error: " + str(exc_type) + " " + str(fname) + " " + str(exc_tb.tb_lineno))
                    raise e
        else:
            raise InvalidArgument(self.obj.store_type())

