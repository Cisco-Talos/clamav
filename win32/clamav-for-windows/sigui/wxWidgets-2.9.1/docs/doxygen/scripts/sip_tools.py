import os

from common import *

class SIPBuilder:
    def __init__(self, doxyparse, outputdir):
        self.doxyparser = doxyparse
        self.output_dir = outputdir

    def make_bindings(self):
        output_dir = os.path.abspath(os.path.join(self.output_dir, "sip"))
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
        for aclass in self.doxyparser.classes:
            if aclass.name in excluded_classes:
                print "Skipping %s" % aclass.name
                continue
        
            header_name = aclass.name[2:].lower()
            filename = os.path.join(output_dir, "_" + header_name + ".sip")
            enums_text = make_enums(aclass)
            method_text = self.make_sip_methods(aclass)
            base_class = get_first_value(aclass.bases)
            if base_class != "":
                base_class = ": %s" % base_class
            
            text = """
%s
class %s %s
{
%%TypeHeaderCode
#include <%s>
%%End

public:
%s
};
""" % (enums_text, aclass.name, base_class, get_first_value(aclass.includes), method_text)

            afile = open(filename, "wb")
            afile.write(text)
            afile.close()


    def make_sip_methods(self, aclass):
        retval = ""
    
        for amethod in aclass.constructors + aclass.methods:
            transfer = ""
            
            # FIXME: we need to come up with a way of filtering the methods out by various criteria
            # including parameters and method name, and how to deal with overloads 
            if aclass.name in ignored_methods:
                should_ignore = False
                for method in ignored_methods[aclass.name]:
                    print "method = %s" % method
                    if method == amethod.name:
                        params = ignored_methods[aclass.name][method]
                        should_ignore = True
                        for i in xrange(len(params)):
                            if i >= len(amethod.params):
                                should_ignore = False
                                break
                            elif amethod.params[i]["type"] != params[i]:
                                print "param type = %s, amethod.param type = %s" % (params[i], amethod.params[i]["type"])
                                should_ignore = False
                                break
                        
                if should_ignore:
                    continue
            
            # We need to let SIP know when wx is responsible for deleting the object.
            # We do this if the class is derived from wxWindow, since wxTLW manages child windows
            # and wxApp deletes all wxTLWs on shutdown
            if amethod in aclass.constructors and self.doxyparser.is_derived_from_base(aclass, "wxWindow"):
                transfer = "/Transfer/"
                
            if amethod.name.startswith("operator"):
                continue
            
            retval += "    %s %s%s%s;\n\n" % (amethod.return_type.replace("virtual ", ""), amethod.name, amethod.argsstring, transfer)
        
        return retval
