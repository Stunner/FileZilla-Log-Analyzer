'''
Created on Jul 10, 2010

FLAmodule version 1.03 alpha

@author: Aaron Jubbal
'''

#!/usr/bin/env python
#Module for parsing FileZilla Server log files

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class InternalError(Error):
    """Raised when situation that is not meant to happen, occurs."""
    
    def __init__(self,errMsg):
        self.errMsg = errMsg
        
    def __str__(self):
        return repr(self.errMsg)

class G:
    nextIndex = 0
    arbitraryIndexVal = 1000000

class event(object):
    def __init__(self,m,p,d,t,u,i,a,c):
        self.message = m #Indicates if line is just a server message instead of an event
        self.port = p
        self.date = d
        self.time = t
        self.user = u
        self.ip = i
        if a[0] == "tuple":
            self.action = a[1]
            self.ignore = a[2]
            self.ignoreFLG = 1
        else:
            self.action = a
            self.ignore = 0
            self.ignoreFLG = 0
        self.line = c+1

#PRIVATE FUNCTIONS:

#remove beginning and ending parenthesis and convert to string
def _parseIP(IPstring):
    return IPstring[1:len(IPstring)-2]

#remove 0th and 7th element(parentheses) and convert to int
def _parsePort(portString):
    #print portString
    return int(portString[1:7])

#recursively join strings until ip address encountered
def _parseUsr(i,fline):
    if fline[i][0] == '(': #if next element is ip address
        G.nextIndex = i
        return fline[i-1]
    else:
        return ' '.join((fline[i-1],_parseUsr(i+1,fline)))

#recursively join strings until newline is reached
def _parseAction(i,fline):
    if fline[i+1] == "\n":
        return fline[i]
    else:
        return ' '.join((fline[i],_parseAction(i+1,fline)))

def findIndexOfItem(item,list):
    for i in range(len(list)):
        if item == list[i]:
            return i
    return G.arbitraryIndexVal
    
#parses entire line
def _parse(line):
    fline = line.split()
    fline.append('\n') #added to indicate when line ends
    #print fline
        
    if fline[0] == "FileZilla" or fline[0] == "Initializing" or \
        fline[0] == "Creating" or fline[0] == "Server" or \
        fline[0] == "Closing" or fline[0] == "Listen" or fline[0] == "Failed":
        G.nextIndex = 0
        m = 1 #line is a message
        a = _parseAction(G.nextIndex,fline) #action
        return (m,-1,'---','---','---','---',a)
        
    else:
        G.nextIndex = 0
        
        m = 0 #line is not a message i.e. contains data to parse
        p = _parsePort(fline[0]) #port number
        d = fline[1] #date
        t = fline[2] #time
        
        indexOfHyphen = findIndexOfItem('-',fline)
        if indexOfHyphen == G.arbitraryIndexVal:
            raise InternalError("Hyphen was never found in _parse().")
        else:
            G.nextIndex = indexOfHyphen+1
            
        u = _parseUsr(G.nextIndex+1,fline) #user
        
        i = _parseIP(fline[G.nextIndex]) #ip address
        G.nextIndex += 1
        
        #print G.nextIndex, fline
        a = _parseAction(G.nextIndex, fline) #action
        
        return (m,p,d,t,u,i,a)


def _parseOriginal(line):
    """Returns original line contents, used in scrambing of information by FLA."""
    
    fline = line.split()
    fline.append('\n') #added to indicate when line ends
    #print fline
        
    if fline[0] == "FileZilla" or fline[0] == "Initializing" or \
        fline[0] == "Creating" or fline[0] == "Server" or \
        fline[0] == "Closing" or fline[0] == "Listen":
        G.nextIndex = 0
        m = 1 #line is a message
        a = _parseAction(G.nextIndex,fline) #action
        return (m,-1,'---','---','---','---','---',a)
        
    else:
        G.nextIndex = 0
        
        m = 0 #line is not a message i.e. contains data to parse
        p = fline[0] #port number
        d = fline[1] #date
        t = fline[2] #time
        
        if fline[3] in ('AM','PM'):
            f = ' '.join((fline[3],fline[4])) #AM/PM and '-'
            G.nextIndex = 5
        elif fline[3] == '-':
            f = fline[3]
            G.nextIndex = 4
        else:
            raise InternalError("Unknown case in _parseOriginal().")
        
        u = _parseUsr(G.nextIndex+1,fline) #user
        
        i = fline[G.nextIndex] #ip address
        G.nextIndex += 1
        
        #print G.nextIndex, fline
        a = _parseAction(G.nextIndex, fline) #action
        #print "returning", (m,p,d,t,f,u,i,a)
        return (m,p,d,t,f,u,i,a)

#PUBLIC FUNCTIONS:
def getLine(line):
    return _parse(line)

def getMesg(line):
    (m,p,d,t,u,i,a) = _parse(file)
    return m

def getPort(line):
    (m,p,d,t,u,i,a) = _parse(file)
    return p
    
def getDate(line):
    (m,p,d,t,u,i,a) = _parse(line)
    return d
    
def getTime(line):
    (m,p,d,t,u,i,a) = _parse(line)
    return t
    
def getUser(line):
    (m,p,d,t,u,i,a) = _parse(line)
    return u

def getIP(line):
    (m,p,d,t,u,i,a) = _parse(line)
    return i
    
def getAction(line):
    (m,p,d,t,u,i,a) = _parse(line)
    return a

def getOriginalLine(line):
    (m,p,d,t,f,u,i,a) = _parseOriginal(line)
    return (m,p,d,t,f,u,i,a)

def stripIP(ip):
    return _parseIP(ip)
    
