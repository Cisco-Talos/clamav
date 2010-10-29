import os

from common import *

class SWIGBuilder:
    def __init__(self, doxyparse, outputdir):
        self.doxyparser = doxyparse
        self.output_dir = outputdir

    def make_bindings(self):
        output_dir = os.path.abspath(os.path.join(self.output_dir, "swig"))
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
        for aclass in self.doxyparser.classes:
            header_name = aclass.name[2:].lower()
            if aclass.name in excluded_classes:
                #print "Skipping %s" % aclass.name
                continue
                
            filename = os.path.join(output_dir, "_" + header_name + ".i")
            enums_text = make_enums(aclass)
            method_text = self.make_swig_methods(aclass)
            text = """
%%newgroup

%s
class %s : publib %s
{

public:
%s
};
""" % (enums_text, aclass.name, get_first_value(aclass.bases), method_text)

            afile = open(filename, "wb")
            afile.write(text)
            afile.close()

        
    def make_swig_methods(self, aclass):
        retval = ""
        
        retval += """
    %%pythonAppend %s    "self._setOORInfo(self)"
    %%pythonAppend %s() ""
    %%typemap(out) %s*; // turn off this typemap
    """ % (aclass.name, aclass.name, aclass.name)
    
        for amethod in aclass.constructors:
            retval += "    %s%s;\n\n" % (amethod.name, amethod.argsstring)
            
        retval += """
        // Turn it back on again
        %%typemap(out) %s* { $result = wxPyMake_wxObject($1, $owner); } 
    """ % aclass.name
    
        for amethod in aclass.methods:
            retval += "    %s %s%s;\n\n" % (amethod.return_type, amethod.name, amethod.argsstring)
        
        return retval
