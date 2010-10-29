"""
Name: doxymlparser.py
Author: Kevin Ollivier
Licence: wxWindows licence
"""

__description__ = """
Takes the output of Doxygen XML and parses it to retrieve metadata about the classes and methods.

To create the Doxygen XML files, from the wxWidgets/docs/doxygen directory, do:

./regen.sh xml

To see the results from parsing a particular class, do:

python doxymlparser.py --report out/xml/classwx_<whatever>.xml
"""

#!/usr/bin/env python
import optparse
import os
import string

import sys
import types

from common import *
from xml.dom import minidom

class ClassDefinition:
    def __init__(self):
        self.name = ""
        self.constructors = []
        self.destructors = []
        self.methods = []
        self.brief_description = ""
        self.detailed_description = ""
        self.includes = []
        self.bases = []
        self.enums = {}
        
    def __str__(self):
        str_repr = """
Class: %s
Bases: %s
Includes: %s
Brief Description: 
%s

Detailed Description:
%s
""" % (self.name, string.join(self.bases, ", "), self.includes, self.brief_description, self.detailed_description)
        str_repr += "Methods:\n"
        
        for method in self.methods:
            str_repr += str(method)
        
        return str_repr

class MethodDefinition:
    def __init__(self):
        self.name = ""
        self.return_type = ""
        self.argsstring = ""
        self.definition = ""
        self.params = []
        self.brief_description = ""
        self.detailed_description = ""
        
    def __str__(self):
        str_repr = """
Method: %s
Return Type: %s
Params: %r
Prototype: %s
Brief Description: 
%s

Detailed Description:
%s
""" % (self.name, self.return_type, self.params, self.definition + self.argsstring, self.brief_description, self.detailed_description)
        return str_repr     

def getTextValue(node, recursive=False):
    text = ""
    for child in node.childNodes:
        if child.nodeType == child.ELEMENT_NODE and child.nodeName == "ref":
            text += getTextValue(child)
        if child.nodeType == child.TEXT_NODE:
            # Add a space to ensure we have a space between qualifiers and parameter names
            text += child.nodeValue.strip() + " "
            
    return text.strip()

def doxyMLToText(node):
    return text

class DoxyMLParser:
    def __init__(self, verbose = False):
        self.classes = []
        self.verbose = verbose

    def find_class(self, name):
        for aclass in self.classes:
            if aclass.name == name:
                return aclass
                
        return None

    def get_enums_and_functions(self, filename, aclass):
        file_path = os.path.dirname(filename)
        enum_filename = os.path.join(file_path, aclass.name[2:] + "_8h.xml")
        if os.path.exists(enum_filename):
            root = minidom.parse(enum_filename).documentElement
            for method in root.getElementsByTagName("memberdef"):
                if method.getAttribute("kind") == "enum":
                    self.parse_enum(aclass, method, root)

    def is_derived_from_base(self, aclass, abase):
        base = get_first_value(aclass.bases)
        while base and base != "":
            
            if base == abase:
                return True
                
            parentclass = self.find_class(base)
            
            if parentclass:
                base = get_first_value(parentclass.bases)
            else:
                base = None
                
        return False

    def parse(self, filename):
        self.xmldoc = minidom.parse(filename).documentElement
        for node in self.xmldoc.getElementsByTagName("compounddef"):
            new_class = self.parse_class(node)
            self.classes.append(new_class)
            self.get_enums_and_functions(filename, new_class)
            
    def parse_class(self, class_node):
        new_class = ClassDefinition()
        new_class.name = getTextValue(class_node.getElementsByTagName("compoundname")[0])
        for node in class_node.childNodes:
            if node.nodeName == "basecompoundref":
                new_class.bases.append(getTextValue(node))
            elif node.nodeName == "briefdescription":
                # let the post-processor determ
                new_class.brief_description = node.toxml()
            elif node.nodeName == "detaileddescription":
                new_class.detailed_description = node.toxml()
            elif node.nodeName == "includes":
                new_class.includes.append(getTextValue(node))

        self.parse_methods(new_class, class_node)

        return new_class
        
    def parse_enum(self, new_class, enum, root):
        enum_name = ""
        enum_values = []
        
        for node in enum.childNodes:
            if node.nodeName == "name":
                enum_name = getTextValue(node)
            elif node.nodeName == "enumvalue":
                enum_values.append(getTextValue(node.getElementsByTagName("name")[0]))
        
        new_class.enums[enum_name] = enum_values
        
    def parse_methods(self, new_class, root):
        for method in root.getElementsByTagName("memberdef"):                
            new_method = MethodDefinition()
            for node in method.childNodes:
                if node.nodeName == "name":
                    new_method.name = getTextValue(node)
                elif node.nodeName == "type":
                    new_method.return_type = getTextValue(node)
                elif node.nodeName == "definition":
                    new_method.definition = getTextValue(node)
                elif node.nodeName == "argsstring":
                    new_method.argsstring = getTextValue(node)
                elif node.nodeName == "param":
                    param = {}
                    for child in node.childNodes:
                        if child.nodeType == child.ELEMENT_NODE:
                            param[child.nodeName] = getTextValue(child)
                    new_method.params.append(param)
            
            if self.verbose:
                print "Adding %s" % (new_method.name + new_method.argsstring)
            
            if new_method.name == new_class.name:
                new_class.constructors.append(new_method)
            elif new_method.name == "~" + new_class.name:
                new_class.destructors.append(new_method)
            else:
                new_class.methods.append(new_method)

if __name__ == "__main__":
    option_dict = { 
                "report"        : (False, "Print out the classes and methods found by this script."),
                "verbose"       : (False, "Provide status updates and other information."),
              }
        
    parser = optparse.OptionParser(usage="usage: %prog [options] <doxyml files to parse>\n" + __description__, version="%prog 1.0")
    
    for opt in option_dict:
        default = option_dict[opt][0]
        
        action = "store"
        if type(default) == types.BooleanType:
            action = "store_true"
        parser.add_option("--" + opt, default=default, action=action, dest=opt, help=option_dict[opt][1])
    
    options, arguments = parser.parse_args()

    if len(arguments) < 1:
        parser.print_usage()
        sys.exit(1)
    
    doxyparse = DoxyMLParser(verbose = options.verbose)
    for arg in arguments:
        doxyparse.parse(arg)        

    if options.report:
        for aclass in doxyparse.classes:
            print str(aclass)

