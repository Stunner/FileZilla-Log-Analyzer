'''
Created on Sep 21, 2010

@author: Aaron Jubbal

Wrapper Script for FLACore.py
'''

"""==================================================================================================================
FileZilla Log Analyzer version 1.10 Alpha by Aaron Jubbal
See README for details. Brief overview of flags:

-p --parse <line number> = parse original log by splitting at login/logout for the session that 
    corresponds with the line number
-s --scramble <[f],[u],[v],[i]> = f: scramble file/folder names
                                  u: scramble user names
                                  v: scramble user names in number format
                                  i: scramble ip addresses
-f --filter <[u],[i],[d],[p]> = u: by user name
                                i: by IP address
                                d: by date
                                p: by port
-d = display login/logout instances
-F = force execution, if a file is going to be overwritten, prompts for overwriting are withheld and the file is
     overwritten
====================================================================================================================="""

import sys

def isPythonVersion(version):
    if float(sys.version[:3]) >= version:
        return True
    else:
        return False

if __name__ == '__main__':
    if not isPythonVersion(2.6):
        print "You are running Python version", sys.version[:3] + ", version 2.6 or 2.7 is required. Please update. Aborting..."
        exit()
    import FLACore
    FLACore.main(sys.argv)
