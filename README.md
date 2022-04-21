## Halogen Library

This repository is a fork of the original [Halogen project](https://github.com/target/halogen)
The idea of this fork is to have a libary version of the project, which lets you use Halogen from any other Python project.

****
Halogen is a tool to automate the creation of yara rules based on the image files embedded within a malicious document. This can assist cyber security professionals in writing detection rules for malicious threats as well as help responders in identifying with particular threat they are dealing with. Currently, Halogen is able to create rules based on JPG and PNG files. 
****

## Halogen Library help 
```
from halogenlib import mfbot

m = mfbot.MFBot()
halogen_hash = m.run("/path/to/document")
yara_rule_content, yara_rule_name = halogen_mfbot.print_yara_rule(halogen_hash, malware="malware family")

```

### Contributing
Please contribute pull requests in python3, and submit any bugs you find as issues.
