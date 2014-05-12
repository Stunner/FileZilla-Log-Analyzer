FileZilla Log Analyzer 1.10 alpha README file.
Author: Aaron Jubbal

--------------------------------------------------------------------------------------------------------------
For best readability, use a viewer that wraps around text, and expand viewing window to length of the above line.

See official FileZilla Log Analyzer thread on the official FileZilla forums at: 
http://forum.filezilla-project.org/viewtopic.php?f=6&t=14719

See Changelog.txt for list of changes.

Disclaimer: I am not responsible for any damage whatsoever done to your system brought upon by the use (or abuse) of this script.

PLEASE NOTE: This README is relatively thorough and there is a good amount of flags and parameters to know, but don't let that intimidate you. The script does a number of integrity checks and will prompt you when something isn't right.

ANOTHER IMPORTANT NOTE: If you ever want to cease script execution for any reason whatsoever, press CTRL+C.

See QuickStart.txt for a quick guide on how to get started, however reading through this README in its entirety is strongly recommended.

##################
Table of Contents:
##################
Overview
License
Requirements
Tools
Third Party Modules Used
Basic Use
Installation
Key
Feature Details
	Analysis
	Encrypting/Scrambling
	Filtering
	Parsing
Additional Flags
	Help
	Force Execution
	Display Sessions
How To Specify Flags
	Some Notes About Parameters
Further Sample Runs
Special Thanks To
Contact

#########
OVERVIEW:
#########
FileZilla Log Analyzer(FLA) features:
- Analysis
	- creates line-by-line interpretation of log file(lineInterpretation.log)
	- creates a summary of all users' actions(files downloaded, uploaded, etc) in log file in a listed format(listedSummary.log)
	**Look in 'Samples' directory for samples and additional information on these files**
- Encrypting/Scrambling
	- creates a replica of original log file, but alters(scrambles) original file/folder names, IP addresses, and/or user names
- Filtering
	- creates filtered files based on each individual value of any combination of the following categories: user name, IP address, date, port
- Parsing
	- creates parsed file(parsedLog.log) by specifying line number ranges, or user login/logout instance
	- can be used alone or in conjunction with encrypting and filtering options

GENERAL USAGE FORMAT: python FLA.py [flags] <log file>

NOTE: All files/folders that are created by FLA.py are created in the directory in which FLA.py resides, even if the log file being analyzed is in a different location.

########
LICENSE:
########
This software is licensed under the GNU General Public License. See GNU GENERAL PUBLIC LICENSE in license directory for a copy. See http://www.gnu.org/licenses/quick-guide-gplv3.html for a quick guide on the license.

#############
REQUIREMENTS:
#############
Support for unix-based systems(Mac OSX, Ubuntu, etc.) and Windows systems(See HowToUseOnWindows.txt for more info).

Python version 2.6 or 2.7.

######
TOOLS:
######
I have included a script(fileMerge.py located in TOOLS directory) to merge files together into one large file. This may come in handy for you if you prefer to have your server logs split by date. Since the current version of FLA can only analyze single files at a time, combining all files into one is necessary. See BASIC USE for more on this.

#########################
THIRD PARTY MODULES USED:
#########################
ipcalc 0.3 <http://pypi.python.org/pypi/ipcalc/0.3> by Wijnand Modderman - Used to determine if ip is scramble-able. MIT license provided as per terms of this module's MIT license agreement.

##########
BASIC USE:
##########
It is best to use this script with complete log files, as using log files that are not continuous can cause problems with the accuracy of results and the execution of the script itself. If your server files are in separate log files themselves you may find the "fileMerge.py" script that I have included to be useful. It will combine all the files into one in the correct order(assuming you didn't change any of the initial file names created by the server).

#############
INSTALLATION:
#############
As this is a script, this can be run from the terminal/command-line directly without any installation required, just make sure you save/unzip the package in a directory and then either move your server log file to that directory, or specify the path to the log file of interest via terminal/command-line. See the the FEATURE DETAILS and ADDITIONAL FLAGS sections for more details on how to use this script.

####
KEY:
####
Key of what the upper-case topics in the 'Feature Details' and 'Additional Flags' represent.

SYNOPSIS: Brief overview of what feature/flag does.

ANALYSIS REQUIRED: If specified, does it require analysis of log file. This is important to know as analysis consists of thorough processing of the log file which generally takes a long time with very large log files. If you can avoid this process to accomplish your goal, it is recommended you do.

FLAG(S): Flag to be specified in command prompt for feature/option to occur. Specified as so: <concise version, verbose version>

CAN BE USED WITH: Provides all flags that can be used in conjunction with feature.

USAGE: Usage format of flag or feature.

EXAMPLE(S): Example of what feature/flag is capable of or information on where to find examples.

################
FEATURE DETAILS:
################
Goes over each core script feature in detail.

========
Analysis
========
SYNOPSIS: Creates line-by-line interpretation of log file(lineInterpretation.log) and a summary of all users' actions(files downloaded, uploaded, etc) in log file in a listed format(listedSummary.log).

To analyze a file, run FLA.py without any flags. The script will analyze the entire log file(can take awhile on large log files) and then write lineInterpretation.log and listedSummary.log.

ANALYSIS REQUIRED: Yes(duh!)

FLAG(S): None, simply give it your log file.

CAN BE USED WITH: -F <force execution>

USAGE: python FLA.py <log file>

EXAMPLE(S): See 'sampleLineInterpretation.log' and 'sampleListedSummary.log' in Samples directory.

$ python FLA.py sampleLog.log 
Analyzing sampleLog.log...
Writing lineInterpretation.log...
Writing listedSummary.log...
$

=====================
Encrypting/Scrambling
=====================
SYNOPSIS: Creates a replica of original log file, but alters(scrambles) original file/folder names, IP addresses, and/or user names.

NOTE: Since FLA is only in alpha, the script also provides a means of preparing the log files for submission to me for bug fixing. The log files can be prepared by parsing and/or encrypting usernames, ips, and/or file/folder names.

Encryption/Scrambling is done as follows: Upon first encounter of a new value it creates a random value(whether it be an IP address, user name, or file/folder) and stores it in a python data type of dictionary with the original authentic value being used as a key. So whenever the real value is encountered again the same "fake" value is used instead.

ANALYSIS REQUIRED: Yes

FLAG(S): -s, --scramble

CAN BE USED WITH: -F <force execution>, -p <parse>

USAGE: python FLA.py -s <scramble parameters> <log file>
	where scramble parameters is any of the following(see Some Notes About Parameters section for info on how to specify parameters):
		f: scramble file/folder names(*1)
                u: scramble user names, cannot be used with 'v' parameter(*2)
                v: scramble user names in number format, cannot be used with 'u' parameter(*3)
                i: scramble ip addresses(*4)

*1:Done by replacing the first file/folder encountered with file_1/folder_1, the second with file_2/folder_2, etc.

*2:Done by choosing a random first name and last name from nameDict.py. Example: Joe Smith, Charles Baker, etc.

*3:Done by replacing the first user name encountered with User_1, the second with User_2, etc.

*4:Scrambling by IP address scrambles only public IPs. Specifically, those that are not in the following CIDR ranges:
	-127.0.0.1/8 (Loopback addresses)
    	-10.0.0.0/8 (Private network)
    	-172.16.0.0/12 (Private network)
    	-192.168.0.0/16 (Private network)
    	-169.254.0.0/16 (Link-local addresses)

EXAMPLE(S): See 'parsedLog1.log' and 'parsedLog2.log' in Samples directory for files created by the below output. First execution corresponds to 'parsedLog1.log' and the second corresponds to 'parsedLog1.log'.

$ python FLA.py -s fui sampleLog.log 
Analyzing sampleLog.log...
Writing parsedLog.log...
$ python FLA.py -s v sampleLog.log 
Analyzing sampleLog.log...
parsedLog.log exists, OK to overwrite? (Y/N)y
Overwriting parsedLog.log...
$

=========
Filtering
=========
SYNOPSIS: Creates filtered files based on each individual value of any combination of the following categories: user name, IP address, date, port.

Filtering should be used when you want to create a log file of a specific user, ip address, date, or port, or any combination thereof. Filtering works by iterating through the original log file while placing each line with a unique value(or combination of unique values) in a separate file, so when finished, you end up with separate log files, one for each variation of your specified value(s). For instance, if you filter by user name alone, FLA will create a filtered log file for each individual value of user name that is present in the specified log file. And if you filter by user name and ip address, FLA will create a filtered log file for each unique combination of user name and ip address. Further combinations work in a similar manner.

Filtering creates a directory with "FL-<log file's name>" and within that, a directory "FL-<specified values to filter by>" and in that directory creates files with "fl-<value of each category>". See examples below.

NOTE: "FL" before the file/directory names stands for "Filtered Log".

ANALYSIS REQUIRED: No

FLAG(S): -f, --filter

CAN BE USED WITH: -F <force execution>, -p <parse>

USAGE: python FLA.py -f <filter parameters> <log file>
	where filter parameters is any of the following(see Some Notes About Parameters section for info on how to specify parameters):
		u: filter by user name
		i: filter by IP address
		d: filter by date
		p: filter by port

EXAMPLE(S): See 'FL-sampleLog.log' directory in Samples folder for filtering examples.

$ python FLA.py -f ui sampleLog.log 
Filtering...
FL-sampleLog.log/FL-User-IP/fl-(not logged in)-8.182.9.128--.log exists, OK to overwrite? (Y/N)y
Overwriting FL-sampleLog.log/FL-User-IP/fl-(not logged in)-8.182.9.128--.log...
FL-sampleLog.log/FL-User-IP/fl-Ben Sanders-8.182.9.128--.log exists, OK to overwrite? (Y/N)y
Overwriting FL-sampleLog.log/FL-User-IP/fl-Ben Sanders-8.182.9.128--.log...
FL-sampleLog.log/FL-User-IP/fl-(not logged in)-200.168.206.142--.log exists, OK to overwrite? (Y/N)y
Overwriting FL-sampleLog.log/FL-User-IP/fl-(not logged in)-200.168.206.142--.log...
FL-sampleLog.log/FL-User-IP/fl-Zorro Jacobs-200.168.206.142--.log exists, OK to overwrite? (Y/N)y
Overwriting FL-sampleLog.log/FL-User-IP/fl-Zorro Jacobs-200.168.206.142--.log...
FL-sampleLog.log/FL-User-IP/fl-(not logged in)-213.14.17.9--.log exists, OK to overwrite? (Y/N)y
Overwriting FL-sampleLog.log/FL-User-IP/fl-(not logged in)-213.14.17.9--.log...
FL-sampleLog.log/FL-User-IP/fl-Abril Young-213.14.17.9--.log exists, OK to overwrite? (Y/N)y
Overwriting FL-sampleLog.log/FL-User-IP/fl-Abril Young-213.14.17.9--.log...

=======
Parsing
=======
SYNOPSIS: Creates parsed file(parsedLog.log) by specifying line number ranges, or user login/logout instance. Can be used alone or in conjunction with encrypting and filtering options.

Parsing can be done in two ways:
	- manually (fast-no file analysis takes place)(i.e. specified line number to specified line number, any parse parameter with a hyphen in it)
	- *automatically, in which the script attempts to parse by user session(slow-file analysis has to take place)

*Highly recommended when parsing for submission for bug fixing, since grabbing entire user sessions makes finding problems much much easier than just viewing a few lines before and after the problem.

Parsing copies a specified(by line numbers) portion of the original log file to a new one. All parsing is inclusive of specified, or generated(*1), line numbers.

ANALYSIS REQUIRED: Depends. If parsing by user session, yes; if manually parsing(hyphen specified in parameter), no.(See above)

FLAG(S): -p, --parse

CAN BE USED WITH: -F <force execution>, -s <scramble>, -f <filter>

USAGE: python FLA.py -p <parse parameters> <log file>
	where parse parameters is any of the following(see Some Notes About Parameters section for info on how to specify parameters):
		<line #>: parse by user login instance at specified line(*2)
		<line #>-: parse from specified line number to end of log file
		-<line #>: parse from beginning of log file to specified line number
		<line #>-<line #>: parse from first specified line number to second specified line number

*1:Lines are generated behind-the-scenes when parsing by user login instance.

*2:A "login instance", or session, is the time/line range in the log file at which a user is logged in. Parsing by user login instance merely parses from the line at which the user logged in at that instance, till the line at which the user logged out. To specify a user login instance to be parsed, you can simply specify the line at which the user logs in/disconnects on or any line number within a login instance. If a line number is specified that does not have a valid user login instance, the script will complain about it. Use the display flag(See ADDITIONAL FLAGS section) to help determine which line number to specify for parsing by user login/logout instances.

For example: "python FLA.py -p 30-76 logFile.log" will create a log file with only lines 30-76 of logFile.log, inclusive. Another example: "python FLA.py -p 96- logFile.log" will create a parsed log file from line 96 to the end of file of logFile.log.

EXAMPLE(S): See 'parsedLog3.log', 'parsedLog4.log', and 'parsedLog5.log' in Samples directory for files created by the below output. First execution corresponds to 'parsedLog3.log', the second corresponds to 'parsedLog4.log', and the third to 'parsedLog5.log'.

$ python FLA.py --parse=-100 sampleLog.log 
Writing parsedLog.log...
$ python FLA.py -p 550- sampleLog.log 
parsedLog.log exists, OK to overwrite? (Y/N)y
Overwriting parsedLog.log...
$ python FLA.py -p=440 sampleLog.log 
Analyzing sampleLog.log...
parsedLog.log exists, OK to overwrite? (Y/N)y
Overwriting parsedLog.log...
$

NOTE: To view which user session the third execution is corresponding to, consult Display Sessions's example.

#################
ADDITIONAL FLAGS:
#################
NOTE: See FEATURE DETAILS for information on feature flags.

====
Help
====
SYNOPSIS: Displays to command-line a brief overview of flags and their usages.

ANALYSIS REQUIRED: No

FLAG(S): -h, --help

CAN BE USED WITH: Nothing else. Must be specified as a stand alone flag.

USAGE: python FLA.py -h <log file>

EXAMPLE(S):

$ python FLA.py --help ../../Samples/sampleLog.log 
=========================================
FileZilla Log Analyzer version 1.10 Alpha
See README for details. Brief overview of flags:
-p --parse <line number> = parse original log by splitting at login/logout for the session that corresponds with the line number
-s --scramble <[f],[u],[v],[i]> = f: scramble file/folder names
                                  u: scramble user names
                                  v: scramble user names in number format
                                  i: scramble ip addresses
-f --filter <[u],[i],[d],[p]> = u: by user name
                                i: by IP address
                                d: by date
                                p: by port
-d = display login/logout instances
-F = force execution, if a file is going to be overwritten, prompts for overwriting are withheld and the file is overwritten
=========================================
$

===============
Force Execution
===============
SYNOPSIS: Doesn't prompt for overwriting files... if a file is going to be overwritten, it will go ahead with it. Can be used with most other flags.

Use when you want to automate the entire script run. User will never be prompted for input.

ANALYSIS REQUIRED: No

FLAG(S): -F

CAN BE USED WITH: -s <scramble>, -f <filter>, -p <parse>

USAGE: python FLA.py -F <log file>

EXAMPLE(S):

$ python FLA.py -F sampleLog.log 
Analyzing sampleLog.log...
Writing lineInterpretation.log...
Writing listedSummary.log...
$ python FLA.py -F sampleLog.log 
Analyzing sampleLog.log...
Overwriting lineInterpretation.log...
Overwriting listedSummary.log...
$

$ python FLA.py --parse -300 sampleLog.log 
Writing parsedLog.log...
$ python FLA.py --parse 500- sampleLog.log 
parsedLog.log exists, OK to overwrite? (Y/N)y
Overwriting parsedLog.log...
$ python FLA.py -F --parse 210-456 --scramble=ui sampleLog.log 
Analyzing sampleLog.log...
Overwriting parsedLog.log...
$

$ python FLA.py -Ff ui sampleLog.log 
Filtering...
Writing FL-sampleLog.log/FL-User-IP/fl-Ben Sanders-8.182.9.128--.log...
Writing FL-sampleLog.log/FL-User-IP/fl-(not logged in)-200.168.206.142--.log...
Writing FL-sampleLog.log/FL-User-IP/fl-Zorro Jacobs-200.168.206.142--.log...
Writing FL-sampleLog.log/FL-User-IP/fl-(not logged in)-213.14.17.9--.log...
Writing FL-sampleLog.log/FL-User-IP/fl-Abril Young-213.14.17.9--.log...
$ python FLA.py -Ff ui sampleLog.log 
Filtering...
Overwriting FL-sampleLog.log/FL-User-IP/fl-(not logged in)-8.182.9.128--.log...
Overwriting FL-sampleLog.log/FL-User-IP/fl-Ben Sanders-8.182.9.128--.log...
Overwriting FL-sampleLog.log/FL-User-IP/fl-(not logged in)-200.168.206.142--.log...
Overwriting FL-sampleLog.log/FL-User-IP/fl-Zorro Jacobs-200.168.206.142--.log...
Overwriting FL-sampleLog.log/FL-User-IP/fl-(not logged in)-213.14.17.9--.log...
Overwriting FL-sampleLog.log/FL-User-IP/fl-Abril Young-213.14.17.9--.log...
$

================
Display Sessions
================
SYNOPSIS: Displays, on command line, list of all user login/logouts. Can't be used with any other flags.

Omits duplicate user logins caused by connecting on more than one port.

ANALYSIS REQUIRED: Yes

FLAG(S): -d

CAN BE USED WITH: Nothing else. Must be specified as a stand alone flag.

USAGE: python FLA.py -d <log file>

EXAMPLE(S):

$ python FLA.py -d sampleLog.log 
Analyzing sampleLog.log...
('Ben Sanders', 'login', 13)
('Ben Sanders', 'disconnect', 78)
('Ben Sanders', 'login', 91)
('Ben Sanders', 'disconnect', 211)
('(not logged in)', 'disconnect', 220)
('Zorro Jacobs', 'login', 233)
('Zorro Jacobs', 'disconnect', 300)
('Ben Sanders', 'login', 313)
('Ben Sanders', 'disconnect', 345)
('Ben Sanders', 'login', 358)
('Ben Sanders', 'disconnect', 367)
('(not logged in)', 'disconnect', 376)
('(not logged in)', 'disconnect', 385)
('(not logged in)', 'disconnect', 394)
('Ben Sanders', 'login', 407)
('Ben Sanders', 'disconnect', 422)
('Abril Young', 'login', 435)
('Abril Young', 'disconnect', 466)
('Ben Sanders', 'login', 479)
('Ben Sanders', 'disconnect', 529)
('(not logged in)', 'disconnect', 538)
('(not logged in)', 'disconnect', 547)
('(not logged in)', 'disconnect', 556)
('Abril Young', 'login', 569)
('Ben Sanders', 'login', 733)
('Ben Sanders', 'disconnect', 866)
('Ben Sanders', 'login', 879)
('Ben Sanders', 'disconnect', 934)
$

#####################
HOW TO SPECIFY FLAGS:
#####################
The flagHandler module that FLA uses has been improved to accept flags in many different ways. Namely, it has been modified to conform to the GNU style of accepting flags(http://www.faqs.org/docs/artu/ch10s05.html). However, flags can still be specified the way they were in previous versions(i.e. -[flag][flag] [param 1] [param 2]). The result is a hybrid of the two styles. Some examples exemplifying the many ways you can specify the same option:

Parse user instance at line 500:

python FLA.py --parse 500 logFile.log

python FLA.py --parse=500 logFile.log

python FLA.py -p 500 logFile.log

python FLA.py -p=500 logFile.log

Parse user instance at line 500 and scramble user names and ip addresses:

python FLA.py -ps 500 ui logFile.log

python FLA.py -sp ui 500 logFile.log

NOTE: Since the parse and scramble flags are concise and both accept parameters, their order relative to one another and the parameters matter.

python FLA.py -p=500 -s ui logFile.log

python FLA.py -p 500 --scramble=ui logFile.log

Parse user instance at line 500 and scramble user names and ip addresses and force execution:

python FLA.py -psF 500 ui logFile.log

python FLA.py -pFs 500 ui logFile.log

python FLA.py -Fps 500 ui logFile.log

NOTE: The position of the 'F' flag is irrelevant as it does not accept any parameters. Position of flags relative to each other only matters if they accept parameters.

python FLA.py -F -p 500 -s ui logFile.log

python FLA.py --parse 500 -s=ui -F logFile.log

python FLA.py -p=500 -sF ui logFile.log

If you specify an option incorrectly the script will stop running and alert you to the problem.

===========================
Some Notes About Parameters
===========================
Only three flags are capable of taking parameters(parse, scramble, filter). Parse accepts number parameters like so: #, -#, #-, #-#(without any white space between hyphen and number(s)). The other two accept letter parameters and each letter that is specified acts as an individual setting. You must specify all these letters as a single parameter to the flag, without any whitespace. So:

'--filter u i' is incorrect

while

'--filter ui' is correct.

See provided examples for each flag for further clarification.

####################
FURTHER SAMPLE RUNS:
####################
Parsing user session at line 440, forcing execution and filtering by user name, ip address, and date:

$ python FLA.py -p=440 -Ff uipd  ../../Samples/sampleLog.log 
Analyzing ../../Samples/sampleLog.log...
Filtering...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-41.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-41.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-42.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-42.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-43.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-200.168.206.142-4.1.2009-44.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Zorro Jacobs-200.168.206.142-4.1.2009-44.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-45.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-45.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-46.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-46.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-47.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-48.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-49.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-50.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-50.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-51.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.1.2009-51.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-52.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-52.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-53.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-53.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-54.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-55.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-56.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-57.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.2.2009-57.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-58.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-59.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.2.2009-59.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.2.2009-58.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.2.2009-60.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.2.2009-60.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.2.2009-61.log...
Overwriting FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.2.2009-61.log...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-41.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-41.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-42.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-42.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-43.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-200.168.206.142-4.1.2009-44.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Zorro Jacobs-200.168.206.142-4.1.2009-44.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-45.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-45.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-46.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-46.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-47.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-48.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-49.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-50.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-50.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.1.2009-51.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-52.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-52.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.1.2009-53.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.1.2009-53.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-54.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-55.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-56.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-57.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.2.2009-57.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-58.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-213.14.17.9-4.2.2009-59.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.2.2009-59.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Abril Young-213.14.17.9-4.2.2009-58.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.2.2009-60.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.2.2009-60.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-(not logged in)-8.182.9.128-4.2.2009-61.log is empty. Removing...
FL-sampleLog.log/FL-User-IP-Date-Port/fl-Ben Sanders-8.182.9.128-4.2.2009-61.log is empty. Removing...
$

Scrambling the first 900 lines of sampleLog.log by files/folders, users, and ip addresses: 

$ python FLA.py --scramble=fvui -p --900 ../../Samples/sampleLog.log 
ParamError: "Flag 'scramble's parameters: 'u' and 'v' conflict."
$ python FLA.py --scramble=fvi -p --900 ../../Samples/sampleLog.log 
There can only be 1 hyphen(-) in flag 'p's parameter. Try again.
$ python FLA.py --scramble=fvi -p -900 ../../Samples/sampleLog.log 
Analyzing ../../Samples/sampleLog.log...
parsedLog.log exists, OK to overwrite? (Y/N)y
Overwriting parsedLog.log...
$

Incorrectly specifying display session and force execution flags together:

$ python FLA.py -dF ../../Samples/sampleLog.log 
FlagError: "Flag '-d' conflicts with '-F'. They cannot be specified together."
$

Displaying sessions:

$ python FLA.py -d logFile.log
Analyzing logFile.log...
('Earl Ming', 'login', 13)
('Earl Ming', 'disconnect', 74)
('Andres Thatcher', 'login', 87)
('Andres Thatcher', 'disconnect', 131)
('Dillan Wilson', 'login', 144)
('Dillan Wilson', 'disconnect', 210)
('Dillan Wilson', 'login', 223)
('Dillan Wilson', 'disconnect', 254)
('Dillan Wilson', 'login', 267)
('Dillan Wilson', 'disconnect', 298)
('Dillan Wilson', 'login', 311)
('Dillan Wilson', 'disconnect', 318)
('Andres Thatcher', 'login', 331)
('Dillan Wilson', 'login', 386)
('Dillan Wilson', 'disconnect', 445)
('Andres Thatcher', 'disconnect', 469)
('Andres Thatcher', 'login', 482)
('Dillan Wilson', 'login', 523)
('Dillan Wilson', 'disconnect', 631)
('Andres Thatcher', 'disconnect', 653)
('Andres Thatcher', 'login', 671)
('Andres Thatcher', 'disconnect', 714)
$

Parses user instance at line 340, so lines 331 to 469[from above] are written to parsedLog.log:

$ python FLA.py -p 340 logFile.log
Analyzing logFile.log...
parsedLog.log exists, OK to overwrite? (Y/N)y
Overwriting parsedLog.log...
$

##################
SPECIAL THANKS TO:
##################
Henry Finucane
Tushar Rawat
Richard Yeh

########
CONTACT:
########
For feedback, comments, questions, bug reporting, or just to give me a friendly hello, contact me at technetix@gmail.com.
