#!/usr/bin/python

# find PHP shells
#
# check for various web shells including:
#       - Weevely
#       - c99 shell
#       - PHP Shell
#       - R57
#       - WSO
#       - FilesMan


import os
import fnmatch
import re
import optparse

parser = optparse.OptionParser()

parser.add_option("-d", type="string", help="Directory to inspect", dest="path", default=".")
parser.add_option("-v", action="store_true", help="Verbose output (list file/line)", dest="verbose")

options, arguments = parser.parse_args()

if options.path:
        path = options.path

# find possible weevely shells
def find_weevely(checkfile):
        found = 0
        check = open(checkfile, "r")
        for line in check:
                if "str_replace" in line:
                        found = 1
        

        if found == 1:
                print checkfile + " - possible Weevely shell! (" + str(os.path.getsize(checkfile)) + " bytes in size)"
                if options.verbose == True:
                        check.seek(0,0)
                        print "\n--- FILE CONTENTS ---"
                        for line in check:
                                print line.strip('\n') 
                        print "--- FILE CONTENTS ---\n"
        

# find other shells with the magic of regex
def find_shells(checkfile, search_str, shell_type):
        found = 0
        suspect_lines = []
        regex = re.compile(search_str)
        check = open(checkfile, "r")
        for line in check:
                if regex.search(line):
                        found = 1
                        if options.verbose == True:
                                # add line into array to print later
                                suspect_lines.append(line)

        if found == 1:
                print checkfile + " - possible " + shell_type + " shell!"               
                if options.verbose == True:
                        for line in suspect_lines:
                                print "Suspect line in " + checkfile + ": " + line.strip('\n')  

print "[=] Start of scan ---\n"

for root, dirs, files in os.walk(path):
        for item in files:
                if fnmatch.fnmatch(item, '*.php'):
                        filepath = root + "/" +  item

                        # check for c99/r57/WSO/FilesMan/PHPShell/etc
                        find_shells(filepath, "R57|r57|C99|c99", "R57/C99")
                        find_shells(filepath, "FilesMan|WSO|wso|wSo", "WSO/FilesMan")


                        # check for weevely
                        if os.path.getsize(filepath) < 1024:
                                find_weevely(filepath)


print "[=] End of scan ---\n"
