#!/usr/bin/env python
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
#TODO: 1) Fix line number inconsistencies between lineInterpretation.log and listedSummary.log - class reconstruction
#        may be in order-> namely storing of the line numbers rather than relying on the itr to represent line nums
#        2) add line numbers of requested command to statistics list containers to help solve issue #1


import sys, FLAmodule, flagHandler, random, nameDict, os, io, ipcalc

#Class of global variables
class G:
    arbitraryIndexVal = 100000 #indicates something wrong occurred or value was not found
    line = 0 #line number
    events = None
    userEvents = []
    userPresent = (0,arbitraryIndexVal) #(if user present, index of user if present)
    prevMsg = 0
    prevUser = ''
    prevPort = ''
    userChanged = 0
    changeList = None #points to changeList class 
    portChanged = 0
    addedStat = 0
    resultsFile = 'results.log'
    analyzedResultsFile = 'lineInterpretation.log'
    statisticsFile = 'listedSummary.log'
    statisticsWriteFile = 'statisticsWrite.log'
    filterLogDir = ''
    subDir = ''
    filterFilePath = ''
    printFlag = 0
    pFlag = False
    fSubFlag = False
    iSubFlag = False
    uSubFlag = False
    vSubFlag = False
    hFlag = False
    fFlag = False
    #filterFlag = False
    dFlag = False
    FFlag = False
    sFlag = False
    sParam = ''
    pParam = ''
    fParam = ''
    specifiedLineNum = -1
    parsedFile = "parsedLog.log"
    parsedList = []
    logFile = ''
    loggedIn = []
    ipDict = {}
    userDict = {}
    fileDict = {}
    pathDict = {}
    fileNum = 1
    pathNum = 1
    userNum = 1
    lC = 0
    discInst = None
    statisticLines = []
    parseTill = -1
    parseFrom = -1
    fullInstanceList = []
    AAs = []
    changeListArray = []
    statistics = []
    userInstancesDict = {}
    begFileTimeList = []
    endFileTimeList = []
    unscrambleableIPs = []


class userPortLst(object):
    def __init__(self,p,d,t,i,a,lC):
        self.port = p
        self.date = []
        self.time = []
        self.ip = []
        self.action =[]
        self.analyzedAction = []
        self.lineNum = []
        self.CWDList = []
        self.statistics = []
        self.stats = None
        self.statisticHolder = None
        self.date.append(d)
        self.time.append(t)
        self.ip.append(i)
        self.action.append(a)
        self.lineNum.append(lC+1)
        self.numEvents = 0
        self.pointer = [0,G.arbitraryIndexVal]
        
        #index counters to help with retrieval of data from lists:
        self.lagParsedIndex = -1
        self.lagStatisticIndex = -1
        self.lagAAIndex = -1
        self.lagListIndex = -1
        self.lagDateIndex = -1
        self.lagTimeIndex = -1
        self.lagIpIndex = -1
        self.lagActionIndex = -1
        
        self.listIndex = 0
        self.statsIndex = 0
        self.userInstances = 0
        self.suspendVal = 0 #designates if line creation needs to be held through to another run
        self.storedAction = ''
        self.storedActionCtr = 0
        self.parsedList = []
    def addEvnt(self,p,d,t,i,a,lC):
        self.date.append(d)
        self.time.append(t)
        self.ip.append(i)
        self.prevAction = self.action[-1]
        self.action.append(a)
        self.lineNum.append(lC+1)
        self.numEvents += 1
        self.pointer[0] += 1
    def addCWD(self,dir):
        self.CWDList.append(dir)
    def getCWD(self):
        if self.CWDList != []:
            return self.CWDList[-1]
        else:
            return '/'
    def store(self,action):
        self.storedActionCtr = 0
        self.storedAction = action
    def getStored(self,specialRequest):
        if specialRequest == True:
            self.storedActionCtr += 1
            return self.storedAction
        else:
            if self.storedActionCtr != 0:
                return ''
            else:
                self.storedActionCtr += 1
                return self.storedAction
    def clearStored(self):
        self.storedAction = ''
        self.storedActionCtr = 0
    def addStatistic(self,s):
        G.statisticLines.append(G.line)
        self.statistics.append(s)
    def holdStatistic(self,s):
        self.statisticHolder = s
    def updateStatistic(self,o,s):
        G.statisticLines.append(G.line)
        if self.statisticHolder[-1] == 'unknown':        
            if o == 1:
                self.statisticHolder[-1] = 'success'
            elif o == 0:
                self.statisticHolder[-1] = 'fail'
        self.statisticHolder.insert(-1,s)
        self.statistics.append(self.statisticHolder)
    def getStatistic(self):
        self.lagStatisticIndex += 1
        return self.statistics[self.lagStatisticIndex]
    def getHeldStatistic(self):
        return self.statisticHolder
    def checkPrevActionEqls(self,str):
        if self.action[-2].split()[0] == str:
            return True
        else:
            return False
    def getLatestAction(self):
        return self.action[-1]
    def appendAA(self,analyzed):
        self.analyzedAction.append(analyzed)
    def getAA(self):
        self.lagAAIndex += 1
        return self.analyzedAction[self.lagAAIndex]
    def suspend(self,value):
        self.suspendVal = value
    def unSuspend(self):
        self.suspendVal = 0
    def ifSuspend(self):
        if self.suspendVal > 0:
            return True
        else:
            return False
    def resetLagListIndex(self):
        self.lagListIndex = -1
        self.lagAAIndex = -1
        self.lagDateIndex = -1
        self.lagTimeIndex = -1
        self.lagIpIndex = -1
        self.lagActionIndex = -1
        self.lagStatisticIndex = -1
        self.lagParsedIndex = -1
    def getDtoA(self): #get Date to Action
        self.lagListIndex += 1
        return (self.date[self.lagListIndex],self.time[self.lagListIndex],\
                self.ip[self.lagListIndex],self.action[self.lagListIndex])
    def createParsedList(self,u,analyzed):
        if grabAfterUser(analyzed[0],1) == 'disconnected.' or grabAfterUser(analyzed[0],2) == 'successfully logged':
            if grabAfterUser(analyzed[0],1) == 'disconnected.':
                self.parsedList.append((u,'disconnect',G.line))
            else:
                self.parsedList.append((u,'login',G.line))
    def getParsed(self):
        self.lagParsedIndex += 1
        return self.parsedList[self.lagParsedIndex]
    def prnt(self):
        print self.action[self.listIndex],
        print self.lineNum[self.listIndex]
        self.listIndex += 1
    def getAllStatistics(self):
        return self.statistics
    
    
    
class userEvntLst(object):
    def __init__(self,p,d,t,u,i,a,lC):
        self.user = u
        self.portsIndex = 0
        self.portList = []
        self.portList.append(userPortLst(p, d, t, i, a, lC))
        self.userInstances = 0
    def addEvnt(self,p,d,t,i,a,lC):
        pI = self.findPortIndex(p)
        if pI != G.arbitraryIndexVal:
            self.portList[pI].addEvnt(p,d,t,i,a,lC)
        else:
            self.portList.append(userPortLst(p,d,t,i,a,lC))
    def findPortIndex(self,p):
        for i in range(len(self.portList)):
            if p == self.portList[i].port:
                return i
        return G.arbitraryIndexVal
    def incUsrInstance(self):
        self.userInstances += 1
        return
    def decUsrInstance(self):
        if self.userInstances > 0:
            self.userInstances -= 1
        return
    def userLoggedIn(self):
        if self.userInstances > 0:
            return True
        else:
            return False
    def addCWD(self,p,dir):
        self.portList[self.findPortIndex(p)].addCWD(dir)
    def getCWD(self,p):
        return self.portList[self.findPortIndex(p)].getCWD()
    def store(self,p,action):
        self.portList[self.findPortIndex(p)].store(action)
    def getStored(self,p,specialRequest):
        return self.portList[self.findPortIndex(p)].getStored(specialRequest)
    def clearStored(self,p):
        return self.portList[self.findPortIndex(p)].clearStored()
    def addStatistic(self,p,s):
        self.portList[self.findPortIndex(p)].addStatistic(s)
    def holdStatistic(self,p,s):
        self.portList[self.findPortIndex(p)].holdStatistic(s)
    def updateStatistic(self,p,o,s):
        self.portList[self.findPortIndex(p)].updateStatistic(o,s)
    def getStatistic(self,p):
        return self.portList[self.findPortIndex(p)].getStatistic()
    def getHeldStatistic(self,p):
        return self.portList[self.findPortIndex(p)].getHeldStatistic()
    def checkPrevActionEqls(self,p,str):
        return self.portList[self.findPortIndex(p)].checkPrevActionEqls(str)
    def getLatestAction(self,p):
        return self.portList[self.findPortIndex(p)].getLatestAction()
    def appendAA(self,p,analyzed):
        self.portList[self.findPortIndex(p)].appendAA(analyzed)
    def getAA(self,p):
        return self.portList[self.findPortIndex(p)].getAA()
    def suspend(self,p,value):
        self.portList[self.findPortIndex(p)].suspend(value)
    def unSuspend(self,p):
        self.portList[self.findPortIndex(p)].unSuspend()
    def ifSuspend(self,p):
        return self.portList[self.findPortIndex(p)].ifSuspend()
    def resetLagListIndex(self,p):
        self.portList[self.findPortIndex(p)].resetLagListIndex()
    def getDtoA(self,p):
        return self.portList[self.findPortIndex(p)].getDtoA()
    def getPort(self,p):
        return self.portList[self.findPortIndex(p)].port
    def createParsedList(self,u,p,analyzed):
        self.portList[self.findPortIndex(p)].createParsedList(u,analyzed)
    def getParsed(self,p):
        return self.portList[self.findPortIndex(p)].getParsed()
    def prnt(self,p):
        print self.user,
        self.portList[self.findPortIndex(p)].prnt()
    def fullStatisticWrite(self,fileToWriteTo,u):
        DLPathDict = {}
        RESTPathDict = {}
        ULPathDict = {}
        APPathDict = {}
        MDPathDict = {}
        RMDPathDict = {}
        DFPathDict = {}
        RNPathDict = {}
        completeUserStats = []
        if u == '---' or u == '(not logged in)': #if message or failed logon, don't bother doing anything-we 
                                                 #don't want their kind 'round here
            return
        for i in range(len(self.portList)):
            completeUserStats.extend(self.portList[i].getAllStatistics())
            
        w = open(fileToWriteTo, 'a')
        w.write(str(u.upper()))
        w.write(':    ')
        writeLoginAndDisc(w,u)
        w.write('\n')
        for j in range(len(completeUserStats)):
            if completeUserStats[j][1] == 'download':
                try:
                    #create dictionary using directories as keys (ie./MY DOCUMENTS)
                    DLPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    DLPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'restart':
                try:
                    RESTPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    RESTPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'upload':
                try:
                    ULPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    ULPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'appended':
                try:
                    APPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    APPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'makedir':
                try:
                    MDPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    MDPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'rmdir':
                try:
                    RMDPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    RMDPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'delete file':
                try:
                    DFPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    DFPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
            if completeUserStats[j][1] == 'rename to':
                try:
                    RNPathDict[completeUserStats[j][4]].append(completeUserStats[j])
                except KeyError:
                    RNPathDict[completeUserStats[j][4]] = [completeUserStats[j]]
        
        if DLPathDict != {}:
            w.write('    ')
            w.write('DOWNLOADS:\n')
            for k,v in DLPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    #             fileA.txt
                    #    fail    fileB.txt    
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
                    
        if RESTPathDict != {}:
            w.write('    ')
            w.write('RESTARTED DOWNLOADS:\n')
            for k,v in RESTPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
                    
        
        if ULPathDict != {}:
            w.write('    ')
            w.write('UPLOADS:\n')
            for k,v in ULPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
        
        if APPathDict != {}:
            w.write('    ')
            w.write('APPENDS:\n')
            for k,v in APPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
        
        if MDPathDict != {}:
            w.write('    ')
            w.write('MADE DIRECTORIES:\n')
            for k,v in MDPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
                    
        if RMDPathDict != {}:
            w.write('    ')
            w.write('REMOVED DIRECTORIES:\n')
            for k,v in RMDPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
                    
        if DFPathDict != {}:
            w.write('    ')
            w.write('DELETED FILES:\n')
            for k,v in DFPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(str(v[i][6]))
                    w.write('\n')
                    counter += 1
                    
        if RNPathDict != {}:
            w.write('    ')
            w.write('RENAMES:\n')
            for k,v in RNPathDict.items():
                counter = 0
                for i in range(len(v)):
                    if counter == 0: #if first run...
                        w.write('    ')
                        w.write('    ')
                        w.write(k) #write directory location
                        w.write(':\n')
                        
                    w.write('    ')
                    if v[i][-1] == 'fail':
                        w.write('fail')
                    else:
                        w.write('    ')
                    w.write('    ')
                    
                    w.write(v[i][5])
                    w.write('    ')
                    w.write(v[i][6])
                    w.write('    ')
                    w.write(str(v[i][7]))
                    w.write('\n')
                    counter += 1
                    
        
        w.close()
        
        
        
    
    
class msgEvntLst(object):
    def __init__(self,m,p,d,t,u,i,a,lC):
        self.message = m
        self.users = []
        self.users.append(userEvntLst(p,d,t,u,i,a,lC))
    def findUserIndex(self,u):
        for i in range(len(self.users)):
            if u == self.users[i].user:
                return i
        return G.arbitraryIndexVal
    def addEvnt(self,p,d,t,u,i,a,lC):
        uI = self.findUserIndex(u)
        if uI != G.arbitraryIndexVal:
            self.users[uI].addEvnt(p,d,t,i,a,lC)
        else:
            self.users.append(userEvntLst(p,d,t,u,i,a,lC))
    def incUsrInstance(self,u):
        self.users[self.findUserIndex(u)].incUsrInstance()
    def decUsrInstance(self,u):
        self.users[self.findUserIndex(u)].decUsrInstance()
    def userLoggedIn(self,u):
        return self.users[self.findUserIndex(u)].userLoggedIn()
    
    def addCWD(self,u,p,dir):
        self.users[self.findUserIndex(u)].addCWD(p,dir)
    def getCWD(self,u,p):
        return self.users[self.findUserIndex(u)].getCWD(p)
    def store(self,u,p,action):
        self.users[self.findUserIndex(u)].store(p,action)
    def getStored(self,u,p,specialRequest):
        return self.users[self.findUserIndex(u)].getStored(p,specialRequest)
    def clearStored(self,u,p):
        return self.users[self.findUserIndex(u)].clearStored(p)
    
    def addStatistic(self,u,p,s):
        self.users[self.findUserIndex(u)].addStatistic(p,s)
    def holdStatistic(self,u,p,s):
        self.users[self.findUserIndex(u)].holdStatistic(p,s)
    def updateStatistic(self,u,p,o,s):
        self.users[self.findUserIndex(u)].updateStatistic(p,o,s)
    def getStatistic(self,u,p):
        return self.users[self.findUserIndex(u)].getStatistic(p)
    def getHeldStatistic(self,u,p):
        return self.users[self.findUserIndex(u)].getHeldStatistic(p)
    def checkPrevActionEqls(self,u,p,str):
        return self.users[self.findUserIndex(u)].checkPrevActionEqls(p,str)
    def getLatestAction(self,u,p):
        return self.users[self.findUserIndex(u)].getLatestAction(p)
    def appendAA(self,u,p,analyzed):
        self.users[self.findUserIndex(u)].appendAA(p,analyzed)
    def getAA(self,u,p):
        return self.users[self.findUserIndex(u)].getAA(p)
    def suspend(self,u,p,value):
        self.users[self.findUserIndex(u)].suspend(p,value)
    def unSuspend(self,u,p):
        self.users[self.findUserIndex(u)].unSuspend(p)
    def ifSuspend(self,u,p):
        return self.users[self.findUserIndex(u)].ifSuspend(p)
    def resetLagListIndex(self,u,p):
        self.users[self.findUserIndex(u)].resetLagListIndex(p)
    def prnt(self,u,p):
        self.users[self.findUserIndex(u)].prnt(p)
    def getItems(self,u,p):
        u = self.users[self.findUserIndex(u)].user
        p = self.users[self.findUserIndex(u)].getPort(p)
        (d,t,i,a) = self.users[self.findUserIndex(u)].getDtoA(p)
        return (p,d,t,u,i,a)
    def createParsedList(self,u,p,analyzed):
        self.users[self.findUserIndex(u)].createParsedList(u,p,analyzed)
    def getParsed(self,u,p):
        return self.users[self.findUserIndex(u)].getParsed(p)
    def fullStatisticWrite(self,fileToWriteTo):
        for i in range(len(self.users)):
            self.users[i].fullStatisticWrite(fileToWriteTo,self.users[i].user)
        
class evntLst(object):
    messages = []
    def __init__(self,m,p,d,t,u,i,a,lC):
        self.messages.append(msgEvntLst(m,p,d,t,u,i,a,lC))
    def findMsgIndex(self,m):
        for i in range(len(self.messages)):
            if m == self.messages[i].message:
                return i
        return G.arbitraryIndexVal
    def addEvnt(self,m,p,d,t,u,i,a,lC):
        mI = self.findMsgIndex(m)
        if mI != G.arbitraryIndexVal:
            self.messages[mI].addEvnt(p,d,t,u,i,a,lC)
        else:
            self.messages.append(msgEvntLst(m,p,d,t,u,i,a,lC))
    def incUsrInstance(self,m,u):
        self.messages[self.findMsgIndex(m)].incUsrInstance(u)
    def decUsrInstance(self,m,u):
        self.messages[self.findMsgIndex(m)].decUsrInstance(u)
    def userLoggedIn(self,m,u):
        return self.messages[self.findMsgIndex(m)].userLoggedIn(u)
    def createLoginList(self,m,u):
        if self.messages[self.findMsgIndex(m)].userLoggedIn(u):
            G.loggedIn.append((True,G.line))
        else:
            G.loggedIn.append((False,G.line))
    def addCWD(self,m,u,p,dir):
        self.messages[self.findMsgIndex(m)].addCWD(u,p,dir)
    def getCWD(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].getCWD(u,p)
    def checkPrevActionEqls(self,m,u,p,str):
        return self.messages[self.findMsgIndex(m)].checkPrevActionEqls(u,p,str)
    def store(self,m,u,p,action):
        self.messages[self.findMsgIndex(m)].store(u,p,action)
    def getStored(self,m,u,p,specialRequest):
        return self.messages[self.findMsgIndex(m)].getStored(u,p,specialRequest)
    def clearStored(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].clearStored(u,p)
    def resetLagListIndex(self,lC):
        m = ''
        u = ''
        p = ''
        for itr in range(lC):
            (tempM,tempU,tempP) = G.changeList.getNext(itr)
            if tempM != '':
                m = tempM
            if tempU != '':
                u = tempU
            if tempP != '':
                p = tempP
            self.messages[self.findMsgIndex(m)].resetLagListIndex(u,p)
    def addStatistic(self,m,u,p,s):
        self.messages[self.findMsgIndex(m)].addStatistic(u,p,s)
    def holdStatistic(self,m,u,p,s):
        self.messages[self.findMsgIndex(m)].holdStatistic(u,p,s)
    def updateStatistic(self,m,u,p,o,s):
        try:
            self.messages[self.findMsgIndex(m)].updateStatistic(u,p,o,s)
        except TypeError:
            print "Error: Log file continuity problem at line " + str(G.line) + \
            ". Most likely due to user or port popping up out of nowhere. Contact developer if you can't figure out what's wrong."
            exit()
    def getStatistic(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].getStatistic(u,p)
    def getHeldStatistic(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].getHeldStatistic(u,p)
    def getLatestAction(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].getLatestAction(u,p)
    def appendAA(self,m,u,p,analyzed):
        self.messages[self.findMsgIndex(m)].appendAA(u,p,analyzed)
    def suspend(self,m,u,p,value):
        self.messages[self.findMsgIndex(m)].suspend(u,p,value)
    def unSuspend(self,m,u,p):
        self.messages[self.findMsgIndex(m)].unSuspend(u,p)
    def ifSuspend(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].ifSuspend(u,p)
    def createParsedList(self,m,u,p,analyzed):
        self.messages[self.findMsgIndex(m)].createParsedList(u,p,analyzed)
    def getParsed(self,m,u,p):
        return self.messages[self.findMsgIndex(m)].getParsed(u,p)

    def fullStatisticWrite(self,fileToWriteTo):
        for i in range(len(self.messages)):
            self.messages[i].fullStatisticWrite(fileToWriteTo)

        
    def compileAnalyzedActions(self):
        for itr in range(len(G.changeListArray)):
            (m,u,p) = G.changeListArray[itr]
            (AA,lineCtr) = self.messages[self.findMsgIndex(m)].getAA(u,p)
            G.AAs.append((AA,lineCtr))
                
    def createLists(self):
        m = ''
        u = ''
        p = ''

        for itr in range(len(G.AAs)):
            (AA,lineCtr) = G.AAs[itr]
            (m,u,p) = G.changeListArray[itr]
            if grabAfterUser(AA,1) == 'disconnected.' or grabAfterUser(AA,2) == 'successfully logged':
                parsed = self.getParsed(m, u, p)
                G.fullInstanceList.append(parsed)
            if found(itr+1,G.statisticLines):
                gotStatistic = self.getStatistic(m, u, p)
                G.statistics.append(gotStatistic)
                
                
    def findLogin(self,logins,item):
        for i in range(len(logins)):
            if logins[i][0] == item[0]:
                if logins[i][1] == 'login':
                    return (logins[i],i)
                print 'problem in func findLogin()'
        return (None,G.arbitraryIndexVal)
    
    def checkForLineInPCandidates(self,parseCandidates):
        for i in range(len(parseCandidates)):
            for j in range(len(parseCandidates[i])):
                if parseCandidates[i][j] == G.specifiedLineNum:
                    return (i,j)
        return (G.arbitraryIndexVal,G.arbitraryIndexVal)
    
    def findMaxOfParseCandidates(self,parseCandidates):
        maxOfParseCandidates = (-1,'---')
        for i in range(len(parseCandidates)):
            if parseCandidates[i][0] > maxOfParseCandidates[0]:
                maxOfParseCandidates = parseCandidates[i]
        return maxOfParseCandidates
    
    #parse log file by user login/logouts
    def parseByLogin(self):
        logins = []
        parseCandidates = []
        for i in range(len(G.fullInstanceList)):
            if i == 12:
                pass
            if G.fullInstanceList[i][1] == 'login': #if login, add to list of logins
                logins.append(G.fullInstanceList[i])
            elif G.fullInstanceList[i][1] == 'disconnect': #if disconnect...
                (login,index) = self.findLogin(logins,G.fullInstanceList[i]) #try to find corresponding login...
                if login != None: #if corresponding login found...
                    try: #add line numbers of login and disconnect to dictionary
                        G.userInstancesDict[G.fullInstanceList[i][0]].append((login[2],G.fullInstanceList[i][2]))
                    except KeyError:
                        G.userInstancesDict[G.fullInstanceList[i][0]] = [(login[2],G.fullInstanceList[i][2])]
                    if login[2] <= G.specifiedLineNum and G.fullInstanceList[i][2] >= G.specifiedLineNum: #if line num between
                                                                                                    # login and disc lines,
                                                                                                    # add to candidates list
                        parseCandidates.append((login[2],G.fullInstanceList[i][2]))
                    del logins[index] #remove used login from list of logins to prevent redundancies
                else: #if corresponding login not found...
                    if G.fullInstanceList[i][0] != '(not logged in)': #...and not a failed login attempt... 
                        try: #add line number of disconnect only to dictionary
                            G.userInstancesDict[G.fullInstanceList[i][0]].append(('---',G.fullInstanceList[i][2]))
                        except KeyError:
                            G.userInstancesDict[G.fullInstanceList[i][0]] = [('---',G.fullInstanceList[i][2])]
                        if G.fullInstanceList[i][2] >= G.specifiedLineNum: #if specified line num less than disc line num...
                            parseCandidates.append((0,G.fullInstanceList[i][2])) #add to candidates list
    #now all logins that are leftover are indicative of users that didn't log out within the log file, and we do the "mirror"
    #of what we did when corresponding logins aren't found
        for i in range(len(logins)):
            try:
                G.userInstancesDict[logins[i][0]].append((logins[i][2],'---'))
            except KeyError:
                G.userInstancesDict[logins[i][0]] = [(logins[i][2],'---')]
            if logins[i][2] <= G.specifiedLineNum:
                parseCandidates.append((logins[i][2],'---'))
        
        if len(parseCandidates) == 0:
            return None
        elif len(parseCandidates) == 1:
            return parseCandidates[0]
        elif len(parseCandidates) >= 1: #if more than one possible parse candidate, we let them fight it out among themselves...
                                        #...well not really, we return the quickest instance, or the instance with the smallest
                                        #difference in line numbers
        #if the specified line number is equal to any login or disconnect line number, we return that instance instead of the
        #smallest
            (itrI,itrJ) = self.checkForLineInPCandidates(parseCandidates)
            if (itrI or itrJ) != G.arbitraryIndexVal:
                return parseCandidates[itrI]
            
        #determine smallest instance and return it...
            lineDiffList = []
            smallestVal = -1
            for i in range(len(parseCandidates)):
                if parseCandidates[i][1] == '---': #disc missing
                    return self.findMaxOfParseCandidates(parseCandidates)
                    #return parseCandidates[i][0],parseCandidates[i][1] 
                lineDiffList.append(parseCandidates[i][1] - parseCandidates[i][0])
            for i in range(len(lineDiffList)):
                if smallestVal == -1:
                    smallestVal = lineDiffList[i]
                if smallestVal > lineDiffList[i]:
                    smallestVal = lineDiffList[i]
            return parseCandidates[findInList(smallestVal,lineDiffList)]

    def parsedPrint(self):
        G.events.resetLagListIndex(G.line-1)
        
        m = ''
        u = ''
        p = ''
        
        for itr in range(len(G.AAs)):
            (AA,lineCtr) = G.AAs[itr]
            (m,u,p) = G.changeListArray[itr]
            if grabAfterUser(AA,1) == 'disconnected.' or grabAfterUser(AA,2) == 'successfully logged':
                print self.getParsed(m, u, p)
            
    def analyzedPrint(self,lC):
        goAhead = False
        m = ''
        u = ''
        p = ''
        
        if not G.FFlag:
            if os.path.exists(G.analyzedResultsFile):
                yn = confirmation(G.analyzedResultsFile + " exists, OK to overwrite? (Y/N)")
                if yn in ('N','n'):
                    print G.analyzedResultsFile, "not overwritten."
                else:
                    goAhead = True
            else:
                goAhead = True
                
        if G.FFlag or goAhead:
            if os.path.exists(G.analyzedResultsFile):
                print "Overwriting", G.analyzedResultsFile + "..."
            else:
                print "Writing", G.analyzedResultsFile + "..."
            
            w = open(G.analyzedResultsFile, 'w')
    
            for itr in range(len(G.AAs)):
                (AA,lineCtr) = G.AAs[itr]    
                (m,u,p) = G.changeListArray[itr]
            
                if AA != '':
                    
                    w.write(AA)
                    w.write(" ")
                    w.write(str(lineCtr+1))
                    w.write("\n")
            w.close()
        
    def statisticWrite(self):
        goAhead = False
        m = ''
        u = ''
        p = ''
        
        if not G.FFlag:
            if os.path.exists(G.statisticsWriteFile):
                yn = confirmation(G.statisticsWriteFile + " exists, OK to overwrite? (Y/N)")
                if yn in ('N','n'):
                    print G.statisticsWriteFile, "not overwritten."
                else:
                    print "Overwriting", G.statisticsWriteFile + "..."
                    goAhead = True
            else:
                goAhead = True
                    
        if G.FFlag or goAhead:
            w = open(G.statisticsWriteFile, 'w')
            for itr in range(len(G.AAs)):
                (AA,lineCtr) = G.AAs[itr]
                (m,u,p) = G.changeListArray[itr]
                
                if found(itr+1,G.statisticLines):
    
                    gotStatistic = self.getStatistic(m, u, p)
                    w.write(str(gotStatistic))
                    w.write(" ")
                    w.write(str(itr+1))
                    w.write("\n")
            w.close()

    def statisticSummaryWrite(self):
        goAhead = False
        
        if not G.FFlag:
            if os.path.exists(G.statisticsFile):
                yn = confirmation(G.statisticsFile + " exists, OK to overwrite? (Y/N)")
                if yn in ('N','n'):
                    print G.statisticsFile, "not overwritten."
                else:
                    goAhead = True
            else:
                goAhead = True
                    
        if G.FFlag or goAhead:
            if os.path.exists(G.statisticsFile):
                print "Overwriting", G.statisticsFile + "..."
            else:
                print "Writing", G.statisticsFile + "..."
            
            w = open(G.statisticsFile, 'w')
            w.write('STATISTICS SUMMARY:')
            w.write('    ')
            w.write(str(tuple(G.begFileTimeList)))
            w.write(' -> ')
            w.write(str(tuple(G.endFileTimeList)))
            w.write('\n')
            w.close()
            
            for itr in range(len(G.AAs)):
                (AA,lineCtr) = G.AAs[itr]
                (m,u,p) = G.changeListArray[itr]
            self.fullStatisticWrite(G.statisticsFile)

    def sortedPrint(self,lC):
        m = ''
        u = ''
        p = ''
        
        w = open(G.resultsFile, 'w')

        for itr in range(len(G.AAs)):
            (AA,lineCtr) = G.AAs[itr]
            (m,u,p) = G.changeListArray[itr]
            (p,d,t,u,i,a) = self.messages[self.findMsgIndex(m)].getItems(u,p)
            w.write(str(p))
            w.write(" ")
            w.write(d)
            w.write(" ")
            w.write(t)
            w.write(" ")
            w.write(u)
            w.write(" ")
            w.write(i)
            w.write(" ")
            w.write(a)
            if AA != '':
                w.write(" AA: ")
                w.write(AA)
                
            w.write("\n")
        w.close()
        
    
        
#tracks the order of changes in users and ports in the log file
class changeList(object):
    cList =[]
    def __init__(self,m,u,p):
        self.cList.append((m,u,str(p)))
    def addMsg(self,m):
        self.cList.append((m,'',''))
    def addUser(self,u):
        self.cList.append(('',u,''))
    def addPort(self,p):
        self.cList.append(('','',str(p)))
    def checkAndUpdate(self,m,u,p):
        if m!= G.prevMsg and u != G.prevUser and p != G.prevPort:
            self.cList.append((m,u,str(p)))
        elif u != G.prevUser and p != G.prevPort:
            self.cList.append((u,str(p)))
        elif m != G.prevMsg:
            print "Message should never show up alone, this is not supported. Contact developer. Aborting..."
            exit()
        elif u != G.prevUser:
            self.addUser(u)
        elif p != G.prevPort:
            self.addPort(str(p))
        else:
            self.cList.append('')

    def prnt(self):
        print self.cList

    def getNext(self,i):
        '''
        Returns (message, user, port)
        '''
        if self.cList[i] == '':
            return ('','','')
        else:
            if type(self.cList[i]) == tuple:
                if len(self.cList[i]) == 2:
                    try:
                        return ('',self.cList[i][0],int(self.cList[i][1]))
                    except:
                        return ('',self.cList[i][0],self.cList[i][1])
                elif len(self.cList[i]) == 3:
                    try:
                        return (self.cList[i][0],self.cList[i][1],int(self.cList[i][2]))
                    except:
                        return (self.cList[i][0],self.cList[i][1],self.cList[i][2])
            else:
                if self.cList[i].isdigit():
                    return ('','',int(self.cList[i]))
                else:
                    return ('',self.cList[i],'')
        
def writeLoginAndDisc(w,u):
    firstLogin = findFirstLogin(u)
    lastDisc = findLastDisc(u)
    if firstLogin == None or lastDisc == None:
        pass
    else:
        if firstLogin[2] > lastDisc[2]:
            firstLogin = None
            lastDisc = None
    w.write(str(firstLogin))
    w.write(' -> ')
    w.write(str(lastDisc))
        
def retrieveStatAtLine(line):
    for itr in range(len(G.statistics)):
        for i in range(len(G.statistics[itr])):
            if type(G.statistics[itr][i]) == tuple:
                if G.statistics[itr][i][-1] == line:
                    return G.statistics[itr]
        
def findLastDisc(u):
    backItr = len(G.fullInstanceList)-1
    for i in range(len(G.fullInstanceList)):
        if G.fullInstanceList[backItr][0] == u and G.fullInstanceList[backItr][1] == 'disconnect':
            return retrieveStatAtLine(G.fullInstanceList[backItr][2])[-1]
        backItr -= 1
    
def findFirstLogin(u):
    for i in range(len(G.fullInstanceList)):
        if G.fullInstanceList[i][0] == u and G.fullInstanceList[i][1] == 'login':
            return retrieveStatAtLine(G.fullInstanceList[i][2])[-1]
        
def compileChangeListArray():
    for itr in range(G.line-1):
        (tempM,tempU,tempP) = G.changeList.getNext(itr)
        if tempM != '':
            m = tempM
        if tempU != '':
            u = tempU
        if tempP != '':
            p = tempP
        G.changeListArray.append((m,u,p))
        
def userInstanceContinuous(loginInst, discInst, fullInstanceList):
        indivUserInstances = 0
        betweenLoginAndDisc = False
        for i in range(len(fullInstanceList)):
            if betweenLoginAndDisc:
                if indivUserInstances == 0:
                    return False
            if fullInstanceList[i][1] == 'login':
                indivUserInstances += 1
            elif fullInstanceList[i][1] == 'disconnect':
                if indivUserInstances > 0:
                    indivUserInstances -= 1
            if loginInst == fullInstanceList[i]:
                betweenLoginAndDisc = True
            if discInst == fullInstanceList[i]:
                betweenLoginAndDisc = False
        return True



def joinFileName(i,fline,length):
    if i+1 == length:
        return fline[i]
    else:
        return ' '.join((fline[i],joinFileName(i+1,fline,length)))

#interpret each line action and do some other housekeeping
def analyze((m,p,d,t,u,i,a),lineCtr):
    msg = ''
    tempM = ''
    parsedAction = a.split()
    if a == '230 Logged on': #######LOGIN#######
        if not G.events.userLoggedIn(m,u):
            msg = "User '" + u + "' successfully logged in."
            G.events.addStatistic(m,u,p,[u,'login',i,p,(d,t,lineCtr+1)])
            if G.printFlag == 1: #for testing purposes
                print msg, lineCtr+1
        G.events.incUsrInstance(m,u)
    elif a == 'disconnected.' or a == 'could not send reply, disconnected.': #######DISCONNECT#######
        G.events.decUsrInstance(m,u)
        if not G.events.userLoggedIn(m,u):
            msg = "User '" + u + "' disconnected."
            G.events.addStatistic(m,u,p,[u,'disconnect',i,p,(d,t,lineCtr+1)])
            if G.printFlag == 1:
                print msg, lineCtr+1
    elif parsedAction[0] == 'RNFR': #######RENAME FROM#######
        A = G.events.getLatestAction(m,u,p)
        G.events.holdStatistic(m,u,p,[u,'rename from',i,p,G.events.getCWD(m,u,p), \
            joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
        tempM = "User '" + u + "' renamed '" + joinFileName(1, A.split(), len(A.split())) + "'."
        G.events.store(m,u,p,tempM)
    elif parsedAction[0] == 'RNTO': #######RENAME TO########
        A = G.events.getLatestAction(m,u,p)
        prevFileName = G.events.getHeldStatistic(m,u,p)[5]
        G.events.holdStatistic(m,u,p,[u,'rename to',i,p,G.events.getCWD(m,u,p), \
            prevFileName,joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
        tempM = "User '" + u + "' renamed '" + G.events.getCWD(m,u,p) + "/" + \
            prevFileName + "' to '" + joinFileName(1, A.split(), len(A.split())) + "'."
        G.events.unSuspend(m,u,p)
        G.events.store(m,u,p,tempM)
    elif parsedAction[0] == '250':
        if parsedAction[1] == 'CWD': #######CHANGE DIR#######
            if grabInParen(a,lineCtr) != G.events.getCWD(m,u,p):
                G.events.addStatistic(m,u,p,[u,'cwd',i,p,G.events.getCWD(m,u,p), \
                    grabInParen(a,lineCtr),(d,t,lineCtr+1),'success'])
                G.events.addCWD(m,u,p,grabInParen(a,lineCtr))
                msg = "User '" + u + "' moved to directory '" + grabInParen(a,lineCtr) + "'." 
        elif parsedAction[1] == 'File' or parsedAction[1] == 'file': 
            if parsedAction[2] == 'deleted': #######REMOVE FILE#######
                msg = G.events.getStored(m,u,p,True)
                G.events.updateStatistic(m,u,p,1,(d,t,lineCtr+1))
            elif parsedAction[2] == 'renamed': #######RENAMED FILE#######
                msg = G.events.getStored(m,u,p,True)
                G.events.updateStatistic(m,u,p,1,(d,t,lineCtr+1))
        if G.printFlag == 1:
            print msg, lineCtr+1
    elif parsedAction[0] == '226' and ((parsedAction[1] == 'ABOR' and parsedAction[2] == 'command') or \
                                       (parsedAction[1] == 'Transfer' and (parsedAction[2] == 'OK' or \
                                                                           parsedAction[2] == 'OK,'))):
        tempM = G.events.getStored(m,u,p,True)
        if grabAfterUser(tempM,2) == 'began downloading' or grabAfterUser(tempM,2) == 'restarted download':
            msg = "User '" + u + "' finished downloading '" + G.events.getHeldStatistic(m,u,p)[5] + "'."
            G.events.updateStatistic(m,u,p,1,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'began uploading':
            msg = "User '" + u + "' finished uploading '" + G.events.getHeldStatistic(m,u,p)[5] + "'."
            G.events.updateStatistic(m,u,p,1,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'began appending':
            msg = "User '" + u + "' finished appending '" + G.events.getHeldStatistic(m,u,p)[5] + "'."
            G.events.updateStatistic(m,u,p,1,(d,t,lineCtr+1))
        elif grabAfterUser(tempM, 2) == 'download of' or grabAfterUser(tempM, 2) == 'upload of' or \
        grabAfterUser(tempM, 2) == 'appending of':
            msg = tempM
        G.events.clearStored(m,u,p)    
            
    elif parsedAction[0] == '200':
        if parsedAction[1] == 'CDUP': #######CHANGE DIR UP#######
            G.events.addStatistic(m,u,p,[u,'cwd',i,p,G.events.getCWD(m,u,p), \
                    grabInParen(a,lineCtr),(d,t,lineCtr+1),'success'])
            G.events.addCWD(m,u,p,grabInParen(a,lineCtr))
            msg = "User '" + u + "' moved to directory '" + grabInParen(a,lineCtr) + "'." 
            if G.printFlag == 1:
                print msg, lineCtr+1
    elif parsedAction[0] == 'RETR': #######DOWNLOAD#######
        if G.events.ifSuspend(m,u,p):
            A = G.events.getLatestAction(m,u,p)
            G.events.holdStatistic(m,u,p,[u,'restart',i,p,G.events.getCWD(m,u,p), \
                joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
            tempM = "User '" + u + "' restarted download of '" + joinFileName(1, A.split(), len(A.split())) + "'."
            G.events.unSuspend(m,u,p)
            G.events.store(m,u,p,tempM)
        else:
            A = G.events.getLatestAction(m,u,p)
            G.events.holdStatistic(m,u,p,[u,'download',i,p,G.events.getCWD(m,u,p), \
                joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
            tempM = "User '" + u + "' began downloading '" + joinFileName(1, A.split(), len(A.split())) + "'."
            G.events.store(m,u,p,tempM)
    elif parsedAction[0] == '150' and parsedAction[1] == 'Connection' and (parsedAction[2] == 'accepted,' or \
                                                                           parsedAction[2] == 'accepted'):
        if G.events.checkPrevActionEqls(m,u,p,'RETR') or G.events.checkPrevActionEqls(m,u,p,'APPE') or \
        G.events.checkPrevActionEqls(m,u,p,'STOR') or G.events.checkPrevActionEqls(m,u,p,'STOU'):
            msg = G.events.getStored(m,u,p,False)
            
    elif parsedAction[0] == 'STOR' or parsedAction[0] == 'STOU': #######UPLOAD#######
        A = G.events.getLatestAction(m,u,p)
        G.events.holdStatistic(m,u,p,[u,'upload',i,p,G.events.getCWD(m,u,p), \
            joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
        tempM = "User '" + u + "' began uploading '" + joinFileName(1, A.split(), len(A.split())) + "'."
        G.events.store(m,u,p,tempM)
    elif parsedAction[0] == 'APPE': #######APPEND#######
        if len(parsedAction) > 1:
            A = G.events.getLatestAction(m,u,p)
            G.events.holdStatistic(m,u,p,[u,'appended',i,p,G.events.getCWD(m,u,p), \
                joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
            tempM = "User '" + u + "' began appending '" + joinFileName(1, A.split(), len(A.split())) + "'."
            G.events.store(m,u,p,tempM)
    elif parsedAction[0] == '350': 
        if parsedAction[1] == 'Rest' and parsedAction[2] == 'supported.' and parsedAction[3] == 'Restarting' and \
            parsedAction[4] == 'at' and int(parsedAction[5]) > 0:
            G.events.suspend(m,u,p,1)
        elif parsedAction[1] == 'File' and parsedAction[2] == 'exists,':
            G.events.suspend(m,u,p,1)
    elif parsedAction[0] == 'DELE': #######DELETE FILE#######
        A = G.events.getLatestAction(m,u,p)
        G.events.holdStatistic(m,u,p,[u,'delete file',i,p,G.events.getCWD(m,u,p), \
            joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),p,'unknown'])
        tempM = "User '" + u + "' deleted file '" + \
            joinFileName(1, A.split(), len(A.split())) + "'."
        G.events.store(m,u,p,tempM)
    elif parsedAction[0] == 'MKD': #######MAKE DIR#######
        A = G.events.getLatestAction(m,u,p)
        G.events.holdStatistic(m,u,p,[u,'makedir',i,p,G.events.getCWD(m,u,p), \
            joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
        tempM = "User '" + u + "' made directory '" + \
            joinFileName(1, A.split(), len(A.split())) + "'."
        G.events.store(m,u,p,tempM)
    elif parsedAction[0] == 'RMD': #######REMOVE DIR#######
        A = G.events.getLatestAction(m,u,p)
        G.events.holdStatistic(m,u,p,[u,'rmdir',i,p,G.events.getCWD(m,u,p), \
            joinFileName(1, A.split(), len(A.split())),(d,t,lineCtr+1),'unknown'])
        tempM = "User '" + u + "' removed directory '" + \
            joinFileName(1, A.split(), len(A.split())) + "'."
        G.events.store(m,u,p,tempM)
    elif parsedAction[0] == '257' and parsedAction[1] == 'Directory' and \
        parsedAction[2] == 'created' and parsedAction[3] == 'successfully': 
        msg = G.events.getStored(m,u,p,True)
        G.events.updateStatistic(m,u,p,1,(d,t,lineCtr+1))
        if G.printFlag == 1:
            print msg, lineCtr+1
    elif parsedAction[0] == '425' and parsedAction[1] == "Can't" and parsedAction[2] == 'open':
        tempM = G.events.getStored(m,u,p,True)
        if grabAfterUser(tempM,2) == 'began downloading':
            msg = "User '" + u + "'s' download of '" + G.events.getHeldStatistic(m,u,p)[5] + \
            "' was canceled, data connection couldn't be opened."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'began uploading':
            msg = "User '" + u + "'s' upload of '" + G.events.getHeldStatistic(m,u,p)[5] + \
            "' was canceled, data connection couldn't be opened."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'began appending':
            msg = "User '" + u + "'s' appending of '" + G.events.getHeldStatistic(m,u,p)[5] + \
            "' was canceled, data connection couldn't be opened."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'restarted download':
            msg = "User '" + u + "'s' attempt to restart download of '" + G.events.getHeldStatistic(m,u,p)[5] + \
            "' was canceled, data connection couldn't be opened."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        G.events.clearStored(m,u,p)
    elif parsedAction[0] == '426' and parsedAction[1] == 'Connection' and parsedAction[2] == 'closed;':
        tempM = G.events.getStored(m,u,p,True)
        tempMsg = ''
        if grabAfterUser(tempM,2) == 'began downloading':
            msg = "User '" + u + "'s' download of '" + G.events.getHeldStatistic(m,u,p)[5] + "' was aborted."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'began uploading':
            msg = "User '" + u + "'s' upload of '" + G.events.getHeldStatistic(m,u,p)[5] + "' was aborted."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        elif grabAfterUser(tempM,2) == 'began appending':
            msg = "User '" + u + "'s' appending of '" + G.events.getHeldStatistic(m,u,p)[5] + "' was aborted."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        G.events.clearStored(m,u,p)    
        
    elif parsedAction[0] == '550':
        index = -1
        
        tempM = G.events.getStored(m,u,p,True)
        G.events.clearStored(m,u,p)
        if parsedAction[1] == "can't" and parsedAction[2] == 'access' and parsedAction[3] == 'file.':
            msg = "Error with user '" + u + "'s' request. Can't access file."
            G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            
        elif parsedAction[1] == 'CWD' and parsedAction[2] == 'failed.':
            G.events.addStatistic(m,u,p,[u,'cwd',i,p,G.events.getCWD(m,u,p), \
                    grabInParen(a,lineCtr),(d,t,lineCtr+1),'fail'])
            G.events.addCWD(m,u,p,grabInParen(a,lineCtr))
            msg = "User '" + u + "' attempted to move to directory '" + grabInParen(a,lineCtr) + "' but failed." 
            
        elif parsedAction[1] == 'Permission' and parsedAction[2] == 'denied':
            if grabAfterUser(tempM,2) == 'removed directory':
                msg = "User '" + u + "' attempted to remove directory '" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            elif grabAfterUser(tempM,2) == 'deleted file':
                msg = "User '" + u + "' attempted to delete file '" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            elif grabAfterUser(tempM,2) == 'made directory':
                msg = "User '" + u + "' attempted to make directory '" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            elif grabAfterUser(tempM,2) == 'began appending':
                msg = "User '" + u + "' attempted to append to file '" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            elif grabAfterUser(tempM,2) == 'began downloading':
                msg = "User '" + u + "' attempted to download file'" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            elif grabAfterUser(tempM,2) == 'began uploading':
                msg = "User '" + u + "' attempted to upload file'" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
            elif grabAfterUser(tempM,2) == 'rename from':
                msg = "User '" + u + "' attempted to rename file'" + \
                    G.events.getHeldStatistic(m,u,p)[5] + "' but failed."
                G.events.updateStatistic(m,u,p,0,(d,t,lineCtr+1))
        
    return (msg,lineCtr)
    
def grabAfterUser(msg,amt):
    splitMsg = msg.split()
    inQuotes = []
    spaceCtr = 0
    quoteCtr = 0
    for i in range(len(msg)):
        if msg[i] == "'":
            quoteCtr += 1
        elif quoteCtr == 1:
            inQuotes.append(msg[i])
        if msg[i] == "'" and quoteCtr == 2:
            for j in range(len(inQuotes)):
                if inQuotes[j] == " ":
                    spaceCtr += 1
            if amt == 1:
                return splitMsg[spaceCtr+2]        
            elif amt == 2:
                return ' '.join((splitMsg[spaceCtr+2],splitMsg[spaceCtr+3]))
            
def grabInQuotes(a):
    A = a.split()
    index = 0
    numQuotes = 0
    begIndex = 0
    endIndex = 0
    for i in range(len(a)):
        if a[i] == '"':
            numQuotes += 1
            if numQuotes == 1:
                begIndex = i
            elif numQuotes == 2:
                endIndex = i
    return a[begIndex+1:endIndex]
            
def grabInParen(a,lineCtr):
    return a.split('"')[1]
    
def detUI(u):
    for j in range(len(G.userEvents)):
        if u == G.userEvents[j].user:
            G.userPresent = (1,j)
            return G.userPresent
    return (0,G.arbitraryIndexVal)

def inUnscrambleableIPs(ip):
    for i in range(len(G.unscrambleableIPs)):
        if ip in G.unscrambleableIPs[i]:
            return True
    return False

def scrambleIP(ip):
    ip = flagHandler.extractIPAddr(ip)
    try:
        return '(' + G.ipDict[ip] + ')>'
    except:
        if inUnscrambleableIPs(ip):
            G.ipDict[ip] = ip #don't scramble
        else:
            scrambledIPs = []
            for i in range(4):
                scrambledIPs.append(str(random.randint(0,255)))
            while '.'.join((scrambledIPs)) == ip or inUnscrambleableIPs('.'.join((scrambledIPs))):
                scrambledIPs = []
                for i in range(4):
                    scrambledIPs.append(str(random.randint(0,255)))    
            G.ipDict[ip] = '.'.join((scrambledIPs))
        return '(' + G.ipDict[ip] + ')>'
    
def scrambleUser(user):
    try:
        return G.userDict[user]
    except:
        newName = ''
        if user == '(not logged in)':
            newName = user
        else:
            if G.vSubFlag:
                newName = 'User_' + str(G.userNum)
                G.userNum += 1
            elif G.uSubFlag:
                newName = nameDict.getRandFirstAndLast()
                while newName == user:
                    newName = nameDict.getRandFirstAndLast()
        G.userDict[user] = newName
        return G.userDict[user]

def scrambleUserInAction(action):
    scrambledUser = ''
    parsedAction = action.split()
    A = action
    beforeUserName = ''
    scrambledAction = ''
    scrambledUser = ''
    if len(parsedAction) > 1:
        if parsedAction[0] == 'USER':
            beforeUserName = parsedAction[0]
            scrambledUser = scrambleUser(' '.join(parsedAction[1:]))
            scrambledAction = ' '.join((beforeUserName,scrambledUser))
        elif parsedAction[0] == '331' and parsedAction[1] == 'Password':
            beforeUserName = ' '.join(parsedAction[:4])
            scrambledUser = scrambleUser(' '.join(parsedAction[4:]))
            scrambledAction = ' '.join((beforeUserName,scrambledUser))
        else:
            return action
        return scrambledAction
    else:
        return action
    
def found(item,lst):
    for i in range(len(lst)):
        if lst[i] == item:
            return True
    return False
    
def scrambleFile(file):
    try:
        return G.fileDict[file]
    except:
        extension = file.split('.')[-1]
        if found('.',file) and len(extension) <= 4:
            newFileName = 'file_' + str(G.fileNum) + '.' + extension
        else:
            newFileName = 'file_' + str(G.fileNum)
        G.fileNum += 1
        G.fileDict[file] = newFileName
        return G.fileDict[file]
    
        
def retrievePath(path):
    try:
        return G.pathDict[path]
    except:
        newPath = 'folder_' + str(G.pathNum)
        G.pathNum += 1
        G.pathDict[path] = newPath
        return G.pathDict[path]

def scramblePath(pathSegLst):
    if pathSegLst == ['','']:
        return ''
    else:
        pathLst = []
        if pathSegLst[0] == '':
            pathSegLst = pathSegLst[1:]
        for i in range(len(pathSegLst)):
            if i != len(pathSegLst)-1:
                pathLst.append(retrievePath(pathSegLst[i]) + '/')
            else:
                pathLst.append(retrievePath(pathSegLst[i]))
        return ''.join(pathLst)

def detSpaces(str):
    splitStr = str.split(' ')
    return len(splitStr)

def scrambleFilesAndFolders(action):
    scrambledFile = ''
    parsedAction = action.split()
    A = action
    beforeFileName = ''
    afterFileName = ''
    scrambledAction = ''
    scrambledUser = ''
    if len(parsedAction) > 1:    
        if (parsedAction[0] == 'MDTM' and parsedAction[1] != 'XPWD') or parsedAction[0] == 'RNFR' or \
        parsedAction[0] == 'RNTO' or parsedAction[0] == 'RETR' or parsedAction[0] == 'STOR' or \
        parsedAction[0] == 'STOU' or parsedAction[0] == 'APPE' or parsedAction[0] == 'DELE':
            beforeFileName = parsedAction[0]
            scrambledFile = scrambleFile(joinFileName(1, A.split(), len(A.split())))
            scrambledAction = ' '.join((beforeFileName,scrambledFile))
        elif parsedAction[0] == 'CWD' or (parsedAction[0] == 'MKD' and parsedAction[1] != 'RNFR') or parsedAction[0] == 'RMD':
            beforeFileName = parsedAction[0]
            if A.split()[1][0] == '/' and A.split()[1] != '/':
                if len(A.split()) > 2:
                    A = ' '.join((A.split()[0],A.split()[1][1:],' '.join(A.split()[2:])))
                else:
                    A = ' '.join((A.split()[0],A.split()[1][1:]))
            if A.split()[1] == '/':
                scrambledPath = '/'
            else:
                splitByFS = joinFileName(1, A.split(), len(A.split())).split('/')
                scrambledPath = scramblePath(splitByFS)
            scrambledAction = ' '.join((beforeFileName,scrambledPath))
        elif (parsedAction[0] == '257' and parsedAction[1] != 'Directory'):
            splitByQuotes = A.split('"')
            splitByFS = []
            splitByFS = splitByQuotes[1].split('/') #grab middle element(the one that was in between quotes)
            beforeFileName = parsedAction[0]
            afterFileName = joinFileName(detSpaces(grabInQuotes(A))+1, A.split(), len(A.split()))
            scrambledPath = '"' + '/' + scramblePath(splitByFS) + '"'
            scrambledAction = ' '.join((beforeFileName,scrambledPath,afterFileName))
        elif (parsedAction[0] == '250' and parsedAction[1] == 'CWD') or \
              (parsedAction[0] == '200' and parsedAction[1] == 'CDUP'):
            splitByQuotes = A.split('"')
            splitByFS = splitByQuotes[1].split('/') #grab middle element(the one that was in between quotes)
            beforeFileName = ' '.join(parsedAction[0:3])
            afterFileName = joinFileName(detSpaces(grabInQuotes(A))+3, A.split(), len(A.split()))
            scrambledPath = '"' + '/' + scramblePath(splitByFS) + '"'
            scrambledAction = ' '.join((beforeFileName,scrambledPath,afterFileName))
        elif (parsedAction[0] == '550' and parsedAction[1] == 'CWD'):
            splitByQuotes = A.split('"')
            splitByFS = splitByQuotes[1].split('/') #grab middle element(the one that was in between quotes)
            beforeFileName = ' '.join(parsedAction[0:3])
            afterFileName = joinFileName(detSpaces(grabInQuotes(A))+3, A.split(), len(A.split()))
            scrambledPath = '"' + '/' + scramblePath(splitByFS) + '":'
            scrambledAction = ' '.join((beforeFileName,scrambledPath,afterFileName))
        else:
            return action
        return scrambledAction
    else:
        return action   


#returns bool value from G.loggedIn list: (True,9),(False,10),...etc
def checkLoginList(lCIndex):
    return G.loggedIn[lCIndex-1][0]

def findInFlagList(item,l):
    for i in range(len(l)):
        if item == l[i][0]:
            return i
    return G.arbitraryIndexVal
    
def findInList(item,lst):
    for i in range(len(lst)):
        if lst[i] == item:
            return i
    return G.arbitraryIndexVal

#extract int values from parsing parameter which may contain hyphens
def decipherParseParam(param):
    """Extracts values of parse flag's parameter."""
    
    numList = param.split('-')
    if len(numList) > 2:
        print "There can only be 1 hyphen(-) in flag 'p's parameter. Try again."
        exit()
    if numList[0] == '' and numList[1] == '':
        print "Must specify line number with hyphen(-) in flag 'p's parameter. Try again."
        exit()
    if numList[0] == '': # -num
        G.parseTill = int(numList[1])
    elif numList[1] == '': # num-
        G.parseFrom = int(numList[0])
    else: # num-num
        G.parseFrom = int(numList[0])
        G.parseTill = int(numList[1])
        if G.parseFrom > G.parseTill:
            print "Second line number must be greater than first in flag 'p's parameter! Try again."
            exit()
            
        
#sets option flags and returns index of next arg item
def processFlags(argv):
    """Determines what flags and parameters have been specified."""
    
    fC = flagHandler.flagConstraints({'h':['h'],'help':['help'],'d':['d']},{'s':['scramble','f','filter'],\
                                                                                'scramble':['s','f','filter'],\
                                                                                'p':['parse'],'f':['filter']})
    pC = flagHandler.paramConstraints({'s':['f','u','i','v'],'scramble':['f','u','i','v'],'f':['i','u','p','d'],\
                                       'filter':['i','u','p','d']},True,['p','parse'],{ 's':( {} , {'u':['v']} ),\
                                                                               'scramble':( {} , {'u':['v']} ) })
    fM = flagHandler.flagManager(['h','help','p','parse','f','filter','d','F','s','scramble'],\
                                 ['p','parse','f','filter','s','scramble'],\
                                 argv,pC,fC)
    G.pParam = fM.getParamForFlag('p') 
    if G.pParam == 'not present':
        G.pParam = fM.getParamForFlag('parse')
    G.fParam = fM.getParamForFlag('f')
    if G.fParam == 'not present':
        G.fParam = fM.getParamForFlag('filter')
    G.sParam = fM.getParamForFlag('s')
    if G.sParam == 'not present':
        G.sParam = fM.getParamForFlag('scramble')
        
    if G.pParam != 'not present':
        G.pFlag = True
        if found('-',G.pParam):
            decipherParseParam(G.pParam)
        else:
            try:
                G.specifiedLineNum = int(G.pParam)
            except:
                print "Flag 'p' requires line number. See README. Terminating..."
                exit()
                
    if fM.flagPresent('h'):
        G.hFlag = True
    if fM.flagPresent('help'):
        G.hFlag = True
    if fM.flagPresent('f'):
        G.fFlag = True
    if fM.flagPresent('filter'):
        G.fFlag = True
    if fM.flagPresent('s'):
        G.sFlag = True
    if fM.flagPresent('scramble'):
        G.sFlag = True
    if fM.flagPresent('d'):
        G.dFlag = True
    if fM.flagPresent('F'):
        G.FFlag = True
        
    for itr in range(len(G.sParam)):
        if G.sParam[itr] == 'f':
            G.fSubFlag = True
        elif G.sParam[itr] == 'u':
            G.uSubFlag = True
        elif G.sParam[itr] == 'v':
            G.vSubFlag = True
        elif G.sParam[itr] == 'i':
            G.iSubFlag = True
        
    return fM.getNextIndex()
    
#will continue to loop if invalid input, once proper input is received, input value is returned 
def confirmation(text):
    yn = raw_input(text)
    if yn not in ('y','Y','n','N'):
        while True:
            yn = raw_input("Incorrect input! Re-enter choice(Y/N): ")
            if yn in ('y','Y','n','N'):
                break
    return yn

def createFilterFileName(line,prevFileName,changedValues=None):
    """Based on line contents, creates file name for each filtered file."""
    
    filterFileName = []
    filterFileName.append('fl') #'fl' stands for 'filtered log'
    (m,p,d,t,f,u,i,a) = FLAmodule.getOriginalLine(line)
    i = flagHandler.extractIPAddr(i)
    p = flagHandler.extractPort(p)
    if changedValues == None and prevFileName == '': #"first run"
        for itr in range(4):
            filterFileName.append('-')
            if itr == 0 and 'u' in G.fParam:
                filterFileName.append(u)
            elif itr == 1 and 'i' in G.fParam:
                filterFileName.append(i)
            elif itr == 2 and 'd' in G.fParam:
                filterFileName.append(d)
            elif itr == 3 and 'p' in G.fParam:
                filterFileName.append(p)
    else:
        splitPrevFileName = os.path.splitext(prevFileName)[0].split('-')[1:]
        for itr in range(len(splitPrevFileName)):
            filterFileName.append('-')
            if changedValues[itr] != None and changedValues[itr] != '':
                filterFileName.append(changedValues[itr])
            else:
                filterFileName.append(splitPrevFileName[itr]) 
    filterFileName.append('.log')
    return makeFitForFileName(''.join(filterFileName))

def generateOutput(toWrite,prevLine=None):
    (m,p,d,t,f,u,i,a) = FLAmodule.getOriginalLine(toWrite)
    if m == 1:
        return ''.join((a,'\n')),[False,[]],True
    if G.fFlag:
        valueChanged = False
        changedValsList = []
        pm = 0
        pp = ''
        pd = ''
        pt = ''
        pf = ''
        pu = ''
        pi = ''
        pa = ''

        if prevLine != None:
            (pm,pp,pd,pt,pf,pu,pi,pa) = FLAmodule.getOriginalLine(prevLine)
        
        for itr in range(4):
            if itr == 0 and 'u' in G.fParam:
                if pu != '' and u != pu:
                    valueChanged = True
                    changedValsList.append(u)
                else:
                    changedValsList.append('')
            elif itr == 1 and 'i' in G.fParam:
                if pi != '' and i != pi:
                    valueChanged = True
                    changedValsList.append(flagHandler.extractIPAddr(i))
                else:
                    changedValsList.append('')
            elif itr == 2 and 'd' in G.fParam:
                if pd != '' and d != pd:
                    valueChanged = True
                    changedValsList.append(d)
                else:
                    changedValsList.append('')
            elif itr == 3 and 'p' in G.fParam:
                if pp != '' and p != pp:
                    valueChanged = True
                    changedValsList.append(flagHandler.extractPort(p))
                else:
                    changedValsList.append('')
            else:
                changedValsList.append('')
        return toWrite,[valueChanged,changedValsList],False
    
    elif G.sFlag:
        if G.iSubFlag:
            i = scrambleIP(i)
        if G.uSubFlag or G.vSubFlag:
            u = scrambleUser(u)
            a = scrambleUserInAction(a)
        if G.fSubFlag:
            a = scrambleFilesAndFolders(a)
    toWrite = ' '.join((p,d,t,f,u,i,a))
    return ''.join((toWrite,'\n')),[False,[]],False 

def makeFitForFileName(name):
    """Converts illegal filename characters to legal ones, namely '/'s to '.'s."""
    
    fittingName = []
    for i in range(len(name)):
        if name[i] == os.sep or name[i] == '/':
            fittingName.append('.')
        else:
            fittingName.append(name[i])
    return ''.join(fittingName)

def pathManager(fileName,writingMode,askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe,createdFileNames,lineNum):
    """Takes care of file location, naming conventions, and confirmation to overwrite filtered files."""
    
    goAhead = False
    subDirName = []
    subDirName.append('FL')
    splitFileName = os.path.splitext(fileName)[0].split('-')
    if splitFileName[1] != '': #user name present
        subDirName.append('-User')
    if splitFileName[2] != '': #ip address present
        subDirName.append('-IP')
    if splitFileName[3] != '': #date present
        subDirName.append('-Date')
    if splitFileName[4] != '': #port present
        subDirName.append('-Port')
    G.subDir = ''.join(subDirName)
    
    G.filterFilePath = G.filterLogDir + os.sep + G.subDir + os.sep + fileName
    if fileName not in createdFileNames:
        if os.path.exists(G.filterFilePath):
            filesThatExistedBeforeExe.append(G.filterFilePath)
    
    if not os.path.exists(G.filterLogDir + os.sep + G.subDir):
        os.makedirs(G.filterLogDir + os.sep + G.subDir)
        print "Writing", G.filterFilePath + "..."
        goAhead = True
    elif os.path.exists(G.filterFilePath):
        if not G.FFlag:
            if writingMode == 'w' and G.filterFilePath not in askedForGoAhead:
                askedForGoAhead.append(G.filterFilePath)
                yn = confirmation(G.filterFilePath + " exists, OK to overwrite? (Y/N)")
                if yn in ('N','n'):
                    print G.filterFilePath, "not overwritten."
                else:
                    print "Overwriting", G.filterFilePath + "..."
                    goAhead = True
        else:
            if G.filterFilePath in filesThatExistedBeforeExe and G.filterFilePath not in showedOverwriting:
                showedOverwriting.append(G.filterFilePath)
                print "Overwriting", G.filterFilePath + "..."
            goAhead = True
    else:
        print "Writing", G.filterFilePath + "..."
        goAhead = True
        
    return G.filterFilePath,goAhead,askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe  

def removeEmptyFiles(createdFileNames):
    """Cycles through all created files and deletes any that are empty."""
    
    for i in range(len(createdFileNames)):
        if os.path.getsize(G.filterLogDir + os.sep + G.subDir + os.sep + createdFileNames[i]) == 0:
            print G.filterLogDir + os.sep + G.subDir + os.sep + createdFileNames[i], "is empty. Removing..."
            os.remove(G.filterLogDir + os.sep + G.subDir + os.sep + createdFileNames[i])
        
def writeLog(loginLineNum,discLineNum):
    """Handles all file writing functionality(parse, scramble, and filter)."""
    
    createdFileNames = []
    askedForGoAhead = []
    showedOverwriting = []
    filesThatExistedBeforeExe = []
    goAhead = False
    isMessage = False
    askedForPConf = False #asked for parsedFile confirmation flag
    if not G.FFlag:
        if not G.fFlag: #p flag or s flag
            askedForPConf = True
            if os.path.exists(G.parsedFile):
                yn = confirmation(G.parsedFile + " exists, OK to overwrite? (Y/N)")
                if yn in ('N','n'):
                    print G.parsedFile, "not overwritten."
                else:
                    print "Overwriting", G.parsedFile + "..."
                    goAhead = True
            else:
                print "Writing parsedLog.log..."
                goAhead = True
            
                
    if G.FFlag or goAhead or G.fFlag:
        w = io.IOBase()
        w.close()
        if not G.fFlag:
            if not askedForPConf:
                if os.path.exists(G.parsedFile):
                    print "Overwriting parsedLog.log..."
                else:
                    print "Writing parsedLog.log..."
            w = open(G.parsedFile, 'w')
        else:
            print "Filtering..."
            G.filterLogDir = 'FL-' + G.logFile.split(os.sep)[-1]
        f = open(G.logFile)
        G.lC = 1
        prevLine = ''
        filterFileName = ''
        for line in f:
            #this block deals with filtering:
            if G.fFlag and G.lC == 1:
                
                filterFileName = createFilterFileName(line,'')
                
                #if os.path.exists(G.parsedFile):
                
                
                filePath,goAhead,askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe = \
                    pathManager(filterFileName,'w',askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe,\
                                createdFileNames,G.lC)
                if goAhead:
                    createdFileNames.append(filterFileName)
                    w = open(filePath,'w')
                generatedLine,changeData,isMessage = generateOutput(line,None)
            else:
                generatedLine,changeData,isMessage = generateOutput(line,prevLine)
                
            if isMessage and G.fFlag: #don't include message in filtered files
                continue
                
            if G.fFlag and changeData[0]:
                    w.close()
                    newFilterFileName = createFilterFileName(line,filterFileName,changeData[1])
                    filterFileName = newFilterFileName
                    if newFilterFileName not in createdFileNames:
                        
                        filePath,goAhead,askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe = \
                            pathManager(filterFileName,'w',askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe,\
                                        createdFileNames,G.lC)
                        if goAhead:
                            createdFileNames.append(newFilterFileName)
                            w = open(filePath,'w')
                    else:
                        filePath,goAhead,askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe = \
                            pathManager(filterFileName,'a',askedForGoAhead,showedOverwriting,filesThatExistedBeforeExe,\
                                        createdFileNames,G.lC)
                        w = open(filePath,'a')
            
            #this block deals with parsed writing/writing 
            if G.parseFrom != -1 and G.parseTill != -1:
                if G.lC >= G.parseFrom and G.lC <= G.parseTill:
                    if not w.closed:
                        w.write(generatedLine)
            elif G.parseTill != -1:
                if G.lC <= G.parseTill:
                    if not w.closed:
                        w.write(generatedLine)
            elif G.parseFrom != -1:
                if G.lC >= G.parseFrom:
                    if not w.closed:
                        w.write(generatedLine)
            
            else:
                if loginLineNum != '---' and loginLineNum != None:
                    if discLineNum != '---' and discLineNum != None:                
                        if G.lC >= loginLineNum and G.lC <= discLineNum:
                            if not w.closed:
                                w.write(generatedLine)
                    else:
                        if G.lC >= loginLineNum:
                            if not w.closed:
                                w.write(generatedLine)
                else:
                    if discLineNum != '---' and discLineNum != None:
                        if G.lC <= discLineNum:
                            if not w.closed:
                                w.write(generatedLine)
                    else: #both login and disc not present
                        if not w.closed:
                            w.write(generatedLine)
            G.lC += 1
            prevLine = line 
            
        f.close()
        w.close()
        
        removeEmptyFiles(createdFileNames)

def initialize():
    """Handles any initialization processes the script needs before running."""
        
    G.unscrambleableIPs.append(ipcalc.Network('127.0.0.1/8')) #Loopback addresses
    G.unscrambleableIPs.append(ipcalc.Network('10.0.0.0/8')) #Private network
    G.unscrambleableIPs.append(ipcalc.Network('172.16.0.0/12')) #Private network
    G.unscrambleableIPs.append(ipcalc.Network('192.168.0.0/16')) #Private network
    G.unscrambleableIPs.append(ipcalc.Network('169.254.0.0/16')) #Link-local addresses
    
def displayHelpMessage():
    print "========================================="
    print "FileZilla Log Analyzer version 1.10 Alpha"
    print "See README for details. Brief overview of flags:"
    print "-p --parse <line number> = parse original log by splitting at login/logout for the session that",\
        "corresponds with the line number"
    print "-s --scramble <[f],[u],[v],[i]> = f: scramble file/folder names"
    print "                                  u: scramble user names"
    print "                                  v: scramble user names in number format"
    print "                                  i: scramble ip addresses"
    print "-f --filter <[u],[i],[d],[p]> = u: by user name"
    print "                                i: by IP address"
    print "                                d: by date"
    print "                                p: by port"
    print "-d = display login/logout instances"
    print "-F = force execution, if a file is going to be overwritten, prompts for overwriting are withheld and the file is",\
        "overwritten"
    print "========================================="
    
def processAndExecute(argv,nextArg):
    """Handles processing and analyzing depending on what flags were specified."""
    
    if G.hFlag:
        displayHelpMessage()
        return
    
    loginInst = None
    discInst = None

    G.logFile = argv[nextArg]
    f = open(G.logFile)
    lineCtr = 0
    G.line = 1
    if (G.pFlag and not G.sFlag and (G.parseFrom != -1 or G.parseTill != -1))  or (G.fFlag and G.specifiedLineNum == -1): 
        #parse without analyzing(i.e. param is #-#)
        if G.parseTill != -1:
            writeLog(loginInst,discInst)
        elif G.parseFrom != -1:
            writeLog(loginInst,discInst)
        elif G.fFlag:
            writeLog(loginInst,discInst)
        else: #just in case something wasn't set properly for some reason...
            print "Flags were set improperly, contact software developer(s)! SEE README for contact info."
        
    else:
        print "Analyzing " + G.logFile + "..."
        for line in f:
            try:
                (m,p,d,t,u,i,a) = FLAmodule.getLine(line)
            except ValueError:
                print "The file's formatting is funky at line " + str(G.line) + \
                    "... Must use an original FileZilla Server log file! Terminating..."
                exit()
            if lineCtr == 0: #if first run
                G.events = evntLst(m,p,d,t,u,i,a,lineCtr)
                G.prevMsg = m
                G.prevUser = u
                G.prevPort = p
                G.changeList = changeList(m,u,p)
                G.begFileTimeList = [d,t,1]
            else:
                G.changeList.checkAndUpdate(m,u,p)
                G.events.addEvnt(m, p, d, t, u, i, a, lineCtr)
            
            
            
            analyzed = analyze((m,p,d,t,u,i,a),lineCtr)
            G.events.createParsedList(m,u,p,analyzed)

            G.events.appendAA(m,u,p,analyzed)
            
            G.endFileTimeList = [d,t,lineCtr+1] #set to very last date, time and line number in the log file
            
            G.prevMsg = m
            G.prevUser = u
            G.prevPort = p
            lineCtr += 1
            G.line += 1
        
        f.close()
        
        ###REQUIRED IN THIS ORDER###
        compileChangeListArray()
        try:
            G.events.compileAnalyzedActions()
        except AttributeError:
            print "Log file specified seems to be empty. Must use a log file with at least one line. Terminating..."
            exit()
        ########END REQUIRE#########
        G.events.createLists()
        G.events.resetLagListIndex(G.line-1)
        
        
        if G.dFlag:
            G.events.parsedPrint()
            G.events.resetLagListIndex(G.line-1)
        else:                
            if G.pFlag or G.sFlag:
                #print "Writing parsedLog.log..."
                if G.pFlag:
                    if G.parseTill != -1:
                        writeLog('---','---')
                    elif G.parseFrom != -1:
                        writeLog('---','---')
                    else:
                        parseByLoginResults = G.events.parseByLogin()
                        if parseByLoginResults == None:
                            print "Invalid line number!" + \
                                  "A user must be logged in at provided line number to parse user's login instance."
                            exit()
                        elif parseByLoginResults[1] == '---': #user disconnection doesn't occur, so simply parse from login to end
                            G.parseFrom = int(parseByLoginResults[0])
                            writeLog('---','---')
                        else:
                            writeLog(parseByLoginResults[0],parseByLoginResults[1])
                else: #u,i, or f used without p
                    writeLog('---','---')
            else:
        
                G.events.resetLagListIndex(lineCtr)
                
                #print "Writing lineInterpretation.log..."
                G.events.analyzedPrint(lineCtr)
                
                #print "Writing statisticsWrite.log..."
                #G.events.statisticWrite()
                
                #print "Writing listedSummary.log..."
                G.events.statisticSummaryWrite()

def main(argv):
    nextArg = 0
    if len(argv) < 2:
        print "Usage: python " + argv[0] + " [flags] <log file>"
        exit()
    initialize()
    #catch errors raised by flagHandler
    try:
        nextArg = processFlags(argv)
    except flagHandler.FlagError as e:
        print "FlagError:",e
        exit()
    except flagHandler.ParamError as e:
        print "ParamError:",e
        exit()

    processAndExecute(argv,nextArg)


if __name__ == '__main__':
    print "Must run FLA.py instead of " + sys.argv[0] + "! Exiting..."
    exit()
