import glob
import os
from halogenlib.lib import parser, generator, render

class MFBot:

    yara_base_file = None
    image_name = None
    dirhash = []
    dir = None
    name = None

    """ Malicious File Bot Class """
    def __init__(self, idat=False, jpgsos=False, sof2sos=False, jump=False) -> None:    
        self.idat = idat
        self.jpgsos = jpgsos
        self.sof2sos = sof2sos
        self.jump = jump
        
    def run(self, yara_base_file):
        """mfbot.run() is the core function to call that will return all information
        generated by mfbot.
        returns: rule_dict - dictionary of rules. """
        self.yara_base_file  = yara_base_file
        self.get_file = parser.get_file(self)
        rule_dict = generator.yara_image_rule_maker(self)
        if rule_dict is not None:
            return rule_dict

    def print_yara_rule(self, rule_list, name=None, malware=None):
        """ prints the yara rule by reading in a list of dicts, and iterating over that.
        parameter: rule_list - list of rules to print. """
        self.name = name
        return render.yara_print_rule(self, rule_list, malware)

    def dir_run(self, dir):
        """ runs through the process with a directory instead of a single file.
        returns: combo list. """
        self.dir = dir
        filelist = glob.glob(self.dir + "/*")
        combo = []
        for f in filelist:
            if os.path.isfile(f):
                self.image_name = None
                self.yara_base_file = f
                self.get_file = parser.get_file(self)
                self.dirhash.append(self.get_file[0])
                rule_dict = generator.yara_image_rule_maker(self)
                if rule_dict is not None:
                    for i in rule_dict:
                        if i not in combo:
                            combo.append(i)
            else:
                pass
        return combo
