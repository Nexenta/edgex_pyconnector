from lxml import etree
from io import StringIO, BytesIO

from edgeerror import (edge_error, InvalidXML, AccessDenied, InvalidURI, \
        Redirect, ServiceError, CommandError, InvalidObject)

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
        content = xmlText.encode('utf8')
        self.root = etree.fromstring(content)
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

