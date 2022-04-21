# coding=utf-8
""" The render library to support all output processes  """
import datetime


def yara_print_rule(self, l, malware=None):
    """ iterate over the list, and print a string for each rule
    parameter: l - list of rules"""
    if self.name:
        rname = str(self.name)
    else:
        rname = "halogen_generated_{md5_hash}".format(md5_hash=self.get_file[0])
    if self.dirhash and len(self.dirhash) < 20:
        md5val = self.dirhash
    else:
        md5val = self.get_file[0]
    if self.dir:
        dir_path = self.dir
        if "\\" in dir_path:
            win_path = dir_path.replace("\\", "\\\\")
            fname = "Directory: {0} ".format(win_path)
        else:
            fname = "Directory: {0} ".format(dir_path)
    else:
        fname = self.yara_base_file
    if not malware:
        malware = "malware family"

    rule_string = """\
rule {rname} : maldoc image
{{
    meta:
        tlp = "amber"
        author = "Halogen Generated Rule"
        date = "{date}"
        family = {malware}
    strings:
""".format(rname=rname, date=str(datetime.date.today()), malware=malware)
    for i in range(0, len(l)):
        rule_dict = l[i]
        ftype = rule_dict['format'].lower()
        image_hex = rule_dict['hex']
        s = "        ${ftype}_img_value_{image_name_string} = {{{image_value_str}}}\n".format(
            ftype=ftype, image_name_string=i, image_value_str=image_hex
        )
        rule_string += s

    rule_string += """
    condition:
        any of them
}"""
    return rule_string, rname
