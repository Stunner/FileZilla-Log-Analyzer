#!/usr/bin/env python


'''========================================================================================================================
flagHandler Module version 1.20 by Aaron Jubbal

Calling program should make an instance of flagManager and use its getter methods to obtain the needed information.

First parameter should be a list of all the flags your program supports, the second parameter should be a list of
the flags whose order matters relative to the other flags. The third parameter is a list of arguments passed into
the calling program. NOTE: The second list of flags must only have flags that are also contained within the allFlags list.

The following list of classes/functions are those that are meant to be called, functions/classes omitted from the following
list are internal to the flagHandler module and are not meant to be called externally.

Key:
[] = variable type

Class:
flagManager
    Class Methods:
        bool flagsSpecified()
        bool duplicateFlagsSpecified()
        bool flagPresent(flag[string])
        list getIllegalFlags()
        list getFlagIndices()
        list getRelOrder()
        list getFlagWithArgList()
        list getErrors()
        int getNextindex()
    
==========================================================================================================================='''

import os


class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class ContentError(Error):
    """Raised when parameter contents conflict, or could potentially conflict."""
    
    def __init__(self,param1,param2,errMsg):
        self.param1 = param1
        self.param2 = param2
        self.errMsg = errMsg
        
    def __str__(self):
        return repr(self.errMsg)
    
class ParamError(Error):
    """Raised when parameters improperly specified."""
    
    def __init__(self,errMsg):
        self.errMsg = errMsg
        
    def __str__(self):
        return repr(self.errMsg)

class FlagError(Error):
    """Raised whenever there is an issue pertaining to specified flags."""
    
    def __init__(self,flg,errMsg):
        self.flag = flg
        self.errMsg = errMsg
        
    def __str__(self):
        return repr(self.errMsg)


#class of globals
class G:
    arbitraryIndexVal = 100000
    #flagDict = {} #flag dictionary holding flags and their corresponding index values
    flags = ''
    
class flagConstraints:
    """Class that handles flag constraints(i.e. flag a cannot be with flag c, flag b cannot be with flag e, etc)"""
    
    def __init__(self,allowable,forbidden):
        if self.__preliminaryErrorCheck(allowable, forbidden):
            self.__allowableFromUser = allowable
            self.__forbiddenFromUser = forbidden
            self.__allowable = {}
            self.__disobeyingConstraintDict = {}
            
        
    def __preliminaryErrorCheck(self,allowable,forbidden):
        if type(allowable) != dict and type(forbidden) != dict:
            raise TypeError("Both parameters to flagConstraints constructor must be of type dictionary.")
            return False
        if not properDictValue(allowable) or not properDictValue(forbidden):
            raise TypeError("Dictionary values must be of type list.")
            return False
        if sameKeyInBothDicts(allowable,forbidden):
            raise ContentError(allowable,forbidden,"Same key cannot be in both dictionaries.")
            return False
        if conflictingConstraints(allowable,forbidden):
            raise ContentError(allowable,forbidden, \
                               "Dictionary values are in conflict with each other.")
            return False
        return True
        
    def __errorCheck(self,allFlags):
        """Error check that requires additional information(allFlags) and needs to take place after called
           by flagManager class"""
        
        if not dictKeysAndValuesWithinSpecifiedList(self.__allowableFromUser,allFlags) or \
                not dictKeysAndValuesWithinSpecifiedList(self.__forbiddenFromUser,allFlags):
            raise ContentError(self.__allowableFromUser,self.__forbiddenFromUser, \
                               "Dictionary keys/values are not legitimate flags.")
            return False
        return True

    def _makeConstraintDict(self,allFlags):
        """Makes flag constraint rules. Converts any forbidden rules to allowable rules and appends them to allowable dict."""
        
        if self.__errorCheck(allFlags):
            self.__allowable = self.__allowableFromUser
            tempDict = {}
            for k,v in self.__forbiddenFromUser.items():
                tempDict[k] = subtractFromList(v,allFlags)
            self.__allowable.update(tempDict)
            
    def __checkKFlagConstraints(self,key,value,flagDict):
        """Helper function to _makeDisobeyingConstraintDict(). Returns all input flags that go against the constraints of a
           specific flag, k."""
           
        DCL = [] #(disobeying constraint list)
        inputFlagsOmittingK = []
        for k,v in flagDict.items():
            inputFlagsOmittingK.append(k)
        #inputFlagsOmittingK = list(inputFlags)
        inputFlagsOmittingK.remove(key)
        if inputFlagsOmittingK != None:
            for i in range(len(inputFlagsOmittingK)):
                if inputFlagsOmittingK[i] not in value:
                    DCL.append(inputFlagsOmittingK[i])
        return DCL

    def _makeDisobeyingConstraintDict(self,args,flagDict):
        """Creates dictionary of all input flags that have defied constraints."""
        
        #inputFlags = list(G.flags)
        for k1,v1 in flagDict.items():
            for k2,v2 in self.__allowable.items():
                if k1 == k2:
                    disobeyingConstraintList = list(set(flagDict) - set(v2))
                    #disobeyingConstraintList = self.__checkKFlagConstraints(k2,v2,flagDict)
                    if disobeyingConstraintList != []:
                        self.__disobeyingConstraintDict[k2] = disobeyingConstraintList
                        
    def _raiseDCDErrors(self):
        if self.__disobeyingConstraintDict != {}:
            for k,v in self.__disobeyingConstraintDict.items():
                if len(k) == 1:
                    kToDisplay = "-" + k
                elif len(k) > 1:
                    kToDisplay = "--" + k
                if len(v[0]) == 1:
                    vToDisplay = "-" + v[0]
                elif len(v[0]) > 1:
                    vToDisplay = "--" + v[0]
                raise FlagError(k,"Flag '" + kToDisplay + "' conflicts with '" + vToDisplay + \
                                "'. They cannot be specified together.")
        
    def getAllowable(self):
        return self.__allowableFromUser
    
    def getForbidden(self):
        return self.__forbiddenFromUser
    
    def getTotAllowable(self):
        return self.__allowable
    
    def getDisobeyingConstraintDict(self):
        return self.__disobeyingConstraintDict
        
class paramConstraints:
    
    def __init__(self,allowableParamDict,treatCharsIndividually,flagsWhoseParamsMayContainHyphens=None,constraints=None):
        self.__allowableParamDict = allowableParamDict
        self.__treatCharsIndividually = treatCharsIndividually
        self._flagsWhoseParamsMayContainHyphens = flagsWhoseParamsMayContainHyphens
        self.__constraints = constraints
        
    def getAllowableParamDict(self):
        return self.__allowableParamDict
    
    def getTreatCharsIndividually(self):
        return self.__treatCharsIndividually
    
    def getFlagsWhoseParamsMayContainHyphens(self):
        return self._flagsWhoseParamsMayContainHyphens
    
    def getConstraints(self):
        return self.__constraints
            
class flagManager:
    #allFlags (aFlags) - all possible flag values
    #paramFlags (pFlags) - all flags that can accept arguments(1 argument per flag)
    #argv - arguments passed in via command line
    def __init__(self,aFlags,pFlags,argv,additionalParams1=None,additionalParams2=None):
        #additional params go into these
        self.__constraints = None
        self.__paramConstraints = None
        self.__determineWhatAdditionalParamsAre(additionalParams1,additionalParams2)
        
        self.__allFlags = aFlags
        self.__paramFlags = pFlags
        self.__args = argv
        #self.__constraints = constraints
        self.__flagToParamList = []
        self.__flagDict = {} #flag dictionary holding flags and their corresponding parameters
        self.__paramsWithHyphenPositions = []
        
        self.__previousConfirmedFlags = []#used by isFlag() to help keep track of legitimate flags
        self.__duplicateFlags = False
        self.__nextIndex = 1 #next non-flag parameter index to begin with
        self.__flagThatReqsParamPos = -1
        self.__illegalFlags = []
        self.__flagIndices = []
        self.__relOrder = [] #relative order list that holds relative order of paramFlags(i.e. -ped = [('p', 0),('d', 1)] )
        self.__flagWithArgList = []
        self.__errors = []
        self.__processFlags()
        
    def __determineWhatAdditionalParamsAre(self,aP1,aP2):
        if isinstance(aP1,flagConstraints):
            self.__constraints = aP1
        if isinstance(aP2,flagConstraints):
            self.__constraints = aP2
        if isinstance(aP1,paramConstraints):
            self.__paramConstraints = aP1
        if isinstance(aP2,paramConstraints):
            self.__paramConstraints = aP2 
            
    def __fetchParamVal(self,argIndex,presentflagsWithParams,i=G.arbitraryIndexVal): #will only be arbInVal when hyphensRemoved = 2
        argAtArgIndexWithoutHyphens,hyphensRemoved = removeHyphens(self.__args[argIndex])
        if hyphensRemoved == 2:
            #self.__nextIndex = argIndex+1+1
            return (self.__args[argIndex+1],argIndex+1)
        elif hyphensRemoved == 1:
            indexInFWP = foundInListIndex(argAtArgIndexWithoutHyphens[i],presentflagsWithParams)
            #self.__nextIndex = argIndex+indexInFWP+1+1
            return (self.__args[argIndex+indexInFWP+1],argIndex+indexInFWP+1)
    
    def __paramErrorCheck(self,fetchedParamArgIndex,flag,fetchedParam,hyphensRemoved):
        #print flag not in self.__paramConstraints.getFlagsWhoseParamsMayContainHyphens() TODO: remove
        if (fetchedParam[0] == '-' or fetchedParam[0] == '--' or \
        (os.path.exists(fetchedParam) and fetchedParamArgIndex == len(self.__args)-1)) and \
        flag not in self.__paramConstraints.getFlagsWhoseParamsMayContainHyphens():#TODO: fetchedParam[0] == '--' makes no sense
            if hyphensRemoved == 1:
                raise ParamError("No parameter specified for '-" + flag + "' flag.")
            elif hyphensRemoved == 2:
                raise ParamError("No parameter specified for '--" + flag + "' flag.")
            
    
    def __obtainParametersForPortion(self,argIndex,flagPortion,hyphensRemoved):
        flagToParamListPortion = []
        if hyphensRemoved == 1:
            presentflagsWithParams = orderedIntersection(list(flagPortion),self.__paramFlags)
            for i in range(len(flagPortion)):
                if flagPortion[i] in presentflagsWithParams:
                    try:
                        fetchedParam,fetchedParamArgIndex = self.__fetchParamVal(argIndex,presentflagsWithParams,i)
                        #self.__nextIndex = fetchedParamArgIndex + 1
                        self.__nextIndex = setIfMax(self.__nextIndex,fetchedParamArgIndex + 1)
                    except IndexError:
                        raise ParamError("No parameter specified for '-" + flagPortion[i] + "' flag.")
                    self.__paramErrorCheck(fetchedParamArgIndex,flagPortion[i],fetchedParam,hyphensRemoved)
                    flagToParamListPortion.append((flagPortion[i], fetchedParam))
                else:
                    #self.__nextIndex = argIndex + 1
                    self.__nextIndex = setIfMax(self.__nextIndex,argIndex + 1)
                    flagToParamListPortion.append((flagPortion[i],None))
        elif hyphensRemoved == 2:
            presentflagsWithParams = []
            if foundInList(flagPortion,self.__paramFlags):
                presentflagsWithParams.append(flagPortion)
            if flagPortion in presentflagsWithParams:
                try:
                    fetchedParam,fetchedParamArgIndex = self.__fetchParamVal(argIndex,presentflagsWithParams)
                    #self.__nextIndex = fetchedParamArgIndex + 1
                    self.__nextIndex = setIfMax(self.__nextIndex,fetchedParamArgIndex + 1)
                except IndexError:
                    raise ParamError("No parameter specified for '--" + flagPortion + "' flag.")
                self.__paramErrorCheck(fetchedParamArgIndex,flagPortion,fetchedParam,hyphensRemoved)
                flagToParamListPortion.append((flagPortion, fetchedParam))
            else:
                #self.__nextIndex = argIndex + 1
                self.__nextIndex = setIfMax(self.__nextIndex,argIndex + 1)
                flagToParamListPortion.append((flagPortion,None))
        return dict(flagToParamListPortion)
    
    def __obtainParametersForEquals(self,argIndex):
        dictToBeReturned = {}
        paramsForEqualsList = []
        splitArgOnEquals = self.__args[argIndex].split('=')
        beforeEquals = splitArgOnEquals[0]
        afterEquals = splitArgOnEquals[1]
        beforeEqualsWithoutHyphens,removedHyphens = removeHyphens(beforeEquals)
        
        if removedHyphens == 1 and len(beforeEqualsWithoutHyphens) != 1:
            raise FlagError(beforeEqualsWithoutHyphens,"'-" + beforeEqualsWithoutHyphens + \
                            "' must be a single flag. Flags that specify parameters with an" + \
                            " equals sign cannot consist of multiple flags.")
        if beforeEqualsWithoutHyphens not in self.__paramFlags:
            if removedHyphens == 1:
                raise ParamError("Flag '-" + beforeEqualsWithoutHyphens + "' does not accept any parameters.")
            elif removedHyphens == 2:
                raise ParamError("Flag '--" + beforeEqualsWithoutHyphens + "' does not accept any parameters.")
        
        #self.__nextIndex = argIndex + 1
        self.__nextIndex = setIfMax(self.__nextIndex,argIndex+1)
        return dict([(beforeEqualsWithoutHyphens,afterEquals)])
        
    def __obtainFlagToParamList(self):
        flagToParamList = []
        for i in range(len(self.__args)):
            if i in self.__paramsWithHyphenPositions: #if parameter with a hyphen, skip it
                continue
            if self.__args[i][0] == '-':
                if hasEqualsSign(self.__args[i]):
                    flagToParamList.append(self.__obtainParametersForEquals(i))
                else:
                    argAtIWithoutHyphens,removedHyphens = removeHyphens(self.__args[i])
                    flagToParamList.append(self.__obtainParametersForPortion(i,argAtIWithoutHyphens,removedHyphens))
        return flagToParamList
    
    
    def __hyphenCanBeInParam(self,index):
        for i in range(len(self.__previousConfirmedFlags)):
            if self.__previousConfirmedFlags[i][2] == 'v' and not self.__previousConfirmedFlags[i][3] and \
                                                              index == self.__previousConfirmedFlags[i][1] + 1:
                if self.__previousConfirmedFlags[i][0] in self.__paramConstraints.getFlagsWhoseParamsMayContainHyphens():
                    return True
            elif self.__previousConfirmedFlags[i][2] == 'c':
                if index in self.__previousConfirmedFlags[i][1]:
                    return True
                """for j in range(len(self.__previousConfirmedFlags[i][0])):
                    if self.__previousConfirmedFlags[i][0][j] in \
                    self.__paramConstraints.getFlagsWhoseParamsMayContainHyphens():
                        return True"""
        return False
    
    def __findIndicesOfNextPossibleHyphenParam(self,conciseFlags,index,equalsParam):
        if equalsParam != '':
            return []
        indexList = []
        for i in range(len(conciseFlags)):
            if conciseFlags[i] in self.__paramFlags:
                indexList.append(index + len(indexList) + 1)
        return indexList
        
    
    def __isFlag(self,arg,index):
        """arg is the argument found in self.__args at position index(i.e. self.__args[index])
        Returns true if argument at position index is indeed a flag(does extensive checking)."""
        
        equalsParam = ''
        if arg[0] == '-':
            if self.__hyphenCanBeInParam(index):
                self.__paramsWithHyphenPositions.append(index)
                return False
            if arg[1] == '-': #double hyphens,one flag is specified at this index
                try:
                    verboseFlag,equalsParam = arg[2:].split('=')
                except ValueError:
                    verboseFlag = arg[2:].split('=')[0]
                if verboseFlag in self.__allFlags:
                    if equalsParam == '':
                        self.__previousConfirmedFlags.append((verboseFlag,index,'v',False))
                    else:
                        self.__previousConfirmedFlags.append((verboseFlag,index,'v',True))
                    return True
                else:
                    raise FlagError(verboseFlag,"'--" + verboseFlag + "' is not a valid flag.")
            else:
                try:
                    conciseFlags,equalsParam = arg[1:].split('=')
                except ValueError:
                    conciseFlags = arg[1:].split('=')[0]
                for i in range(len(conciseFlags)):
                    if conciseFlags[i] not in self.__allFlags:
                        raise FlagError(conciseFlags,"'-" + conciseFlags + "' is not a valid flag.")
                nextPossibleHyphenParamIndicesList = self.__findIndicesOfNextPossibleHyphenParam(conciseFlags,index,equalsParam)
                if equalsParam == '':
                    self.__previousConfirmedFlags.append((conciseFlags,nextPossibleHyphenParamIndicesList,'c',False))
                else:
                    self.__previousConfirmedFlags.append((conciseFlags,nextPossibleHyphenParamIndicesList,'c',True))
                return True            
        return False
        
    
    #TODO: implement checking feature for subparams('fui' of -f=fui)
    def __formatCheck(self):
        """Checks to ensure that all provided flags are valid and specified properly."""
        
        for i in range(len(self.__args)):
            if self.__isFlag(self.__args[i],i):
                #if self.__args[i][0] == '-':
                argAtISplitAtEquals = self.__args[i].split('=')
                argAtIWithoutHyphensOrEquals,hyphensRemoved = removeHyphens(argAtISplitAtEquals[0])
                #argAtIWithoutHyphensOrEquals, numEqualsRemoved= removeCharFromString('=',argAtIWithoutHyphens)
                #argAtIWithoutHyphensSplitAtEquals = argAtIWithoutHyphens.split('=')
                #argAtIWithoutHyphensOrEquals = argAtIWithoutHyphensSplitAtEquals[0]
                if hyphensRemoved == 1:
                    for j in range(len(argAtIWithoutHyphensOrEquals)):
                        if not foundInList(argAtIWithoutHyphensOrEquals[j],self.__allFlags):
                            raise FlagError(argAtIWithoutHyphensOrEquals[j],"'-" + argAtIWithoutHyphensOrEquals[j] + \
                                            "' is not a valid flag.")
                elif hyphensRemoved == 2:
                    if len(argAtIWithoutHyphensOrEquals) <= 1:
                        raise FlagError(argAtIWithoutHyphensOrEquals,"'--" + argAtIWithoutHyphensOrEquals + \
                                        "' must be a verbose flag(be more than one letter).")
                    if not foundInList(argAtIWithoutHyphensOrEquals,self.__allFlags):
                        raise FlagError(argAtIWithoutHyphensOrEquals,"'--" + argAtIWithoutHyphensOrEquals + \
                                        "' is not a valid flag.")
                elif hyphensRemoved >= 3:
                    raise FlagError(argAtIWithoutHyphensOrEquals,"The flag '" + argAtIWithoutHyphensOrEquals + \
                                    "' has too many hyphens before it.")
    
    def __makeFlagDict(self):
        for i in range(len(self.__flagToParamList)):
            for k,v in self.__flagToParamList[i].items():
                try: #retrieving established flag index value
                    garbageVal = self.__flagDict[k]
                    return True #duplicate flags found
                except: #create new dictionary entry
                    self.__flagDict[k] = v
        return False #duplicate flags not found
            
    def __fineTuneNextIndex(self):
        """If nextIndex points to an invalid position in the argument list, set it to None."""
        
        try:
            self.__args[self.__nextIndex]
        except IndexError:
            self.__nextIndex = None
            
    def __checkParamConstraints(self):
        for k1,v1 in self.__flagDict.items():
            for k2,v2 in self.__paramConstraints.getConstraints().items():
                if k1 == k2:
                    if self.__paramConstraints.getTreatCharsIndividually():
                        for k3,v3 in v2[1].items():
                            if k3 in v1: #if 'u' of {'u':['v']} in 'fui', check to see if bad param exists
                                for i in range(len(v3)): #s's parameters(i.e fui)
                                    if v3[i] in v1:
                                        raise ParamError("Flag '" + k1 + "'s parameters: '" + k3 + "' and '" \
                                                         + v3[i] + "' conflict.")
                
    
    def __enforceParamConstraints(self):
        """Checks if parameter constraints are obeyed, if not raises exceptions."""
        
        for k1,v1 in self.__flagDict.items():
            for k2,v2 in self.__paramConstraints.getAllowableParamDict().items():
                if k1 == k2:
                    if self.__paramConstraints.getTreatCharsIndividually() and len(v1)>1:
                        for i in range(len(v1)):
                            if v1[i] not in v2:
                                raise ParamError("Flag '" + k1 + "''s specified parameter '" + v1[i] + "' is invalid.")
                    else:
                        if v1 not in v2:
                            raise ParamError("Flag '" + k1 + "''s parameter '" + v1 + "' is invalid.")
        self.__checkParamConstraints()
    
    #__init__ helper
    def __processFlags(self):
        """Runs checks and data harvesting methods to retrieve flag information."""
        
        if checkForFlags(self.__args):
            self.__formatCheck() #TODO: Implement for equals param method as well
            #if self.__equalsSubParams != {}:
            
            self.__flagToParamList = self.__obtainFlagToParamList()
            self.__duplicateFlags = self.__makeFlagDict()
            #self.__illegalFlags = checkForIllegalFlags(self.__allFlags)
            #self.__flagIndices = findFlagIndices(self.__allFlags,self.__args)
            #self.__relOrder = findRelativeOrder(findFlagIndices(self.__paramFlags,self.__args))
            #self.__flagWithArgList, self.__errors = concatFlagWithArgList(self.__flagIndices, self.__relOrder,self.__args)
            #self.__nextIndex = findNextIndex(self.__flagWithArgList, self.__args)
            if self.__paramConstraints != {}:
                self.__enforceParamConstraints()
            if self.__constraints != None:
                self.__constraints._makeConstraintDict(self.__allFlags)
                self.__constraints._makeDisobeyingConstraintDict(self.__args,self.__flagDict)
                self.__constraints._raiseDCDErrors()
        self.__fineTuneNextIndex()
    
    def flagsSpecified(self):
        """returns bool value dependent upon if flags are specified(shouldn't be solely used to determine error in flag input)"""
        return len(G.flags) > 0
    
    def duplicateFlagsSpecified(self):
        """returns bool value if the same flag was specified twice by the user"""
        return self.__duplicateFlags
    
    def flagPresent(self, flag):
        """returns bool value depending on if flag was specified by user"""
        return flag in self.__flagDict
        #return foundInTuplesList(flag, self.__flagIndices)
            
    #getters
    def getParamForFlag(self,flag):
        try:
            return self.__flagDict[flag]
        except KeyError:
            if flag not in self.__allFlags:
                raise FlagError(flag,"Requested parameter retrieval of invalid flag.")
            else: #flag not specified
                return 'not present'
    
    def getConstraints(self):
        return self.__constraints
    
    def getEqualsSubParams(self):
        return self.__equalsSubParams
    
    def getIllegalFlags(self):
        return self.__illegalFlags
            
    def getFlagIndices(self):
        return self.__flagIndices
    
    def getRelOrder(self):
        return self.__relOrder
    
    def getFlagWithArgList(self):
        return self.__flagWithArgList
    
    def getErrors(self):
        return self.__errors
    
    def getNextIndex(self):
        return self.__nextIndex
    
    def getFlagToParamList(self):
        return self.__flagToParamList
    
    def getFlagDict(self):
        return self.__flagDict
    
    def getDisobeyingConstraintDict(self):
        return self.__constraints.getDisobeyingConstraintDict()
    
def setIfMax(initialVal,newVal):
    if newVal > initialVal:
        return newVal
    else:
        return initialVal
    
def hasEqualsSign(someString):
    for i in range(len(someString)):
        if someString[i] == '=':
            return True
    return False

def removeCharFromString(char,st):
    charRemovedCtr = 0
    newStrList = []
    for i in range(len(st)):
        if st[i] == st:
            charRemovedCtr += 1
            continue
        newStrList.append(st)
    return ''.join(newStrList), charRemovedCtr
    
def removeHyphens(someString):
    hyphensRemoved = 0
    newStringList = []
    for i in range(len(someString)):
        if someString[i] == '-':
            hyphensRemoved += 1
            continue
        newStringList.append(someString[i])
    return ''.join(newStringList),hyphensRemoved
    
def orderedIntersection(a,b):
    inAandB = []
    for i in range(len(a)):
        if foundInList(a[i],b):
            inAandB.append(a[i])
    return inAandB
    
def intersection(a,b):
    return set(a) & set(b)
    
def isInDenyDictKeys(item,forbidden):
    for key in forbidden.keys():
        if item == key:
            return True,forbidden[key]
    return False, None
    
def conflictingConstraints(allowable,forbidden):
    for k1,v1 in allowable.items():
        for i in range(len(v1)):
            boolVal,keyVal = isInDenyDictKeys(v1[i],forbidden)
            if boolVal:
                if foundInList(k1,keyVal):
                    return True
    return False

def dictKeysAndValuesWithinSpecifiedList(dictionary,dictValueList):
    for k,v in dictionary.items():
        if not foundInList(k,dictValueList):
            return False
        for i in range(len(v)):
            if not foundInList(v[i],dictValueList):
                return False
    return True
    
def properDictValue(dictionary):
    for k,v in dictionary.items():
        if type(v) != list:
            return False
    return True

''' 
def duplicateValueInDict(dictionary):
    tempDict = {}
    for key in dictionary.iterkeys():
        try:
            tempDict[key]
            #if it makes it here, the above line didn't cause an exception, meaning a value was present twice
            return True
        except:
            tempDict[key] = 1
    return False
'''
        
def foundInListIndex(item,lst):
    for i in range(len(lst)):
        if lst[i] == item:
            return i
    return G.arbitraryIndexVal


def foundInList(item,lst):
    for i in range(len(lst)):
        if lst[i] == item:
            return True
    return False

def sameItemInBothLists(obj1,obj2):
    for i in range(len(obj1)):
        for j in range(len(obj2)):
            if obj1[i] == obj2[j]:
                return True
    return False

def sameKeyInBothDicts(dict1,dict2):
    dict1Keys = []
    dict2Keys = []
    for key1 in dict1.iterkeys():
        dict1Keys.append(key1)
    for key2 in dict2.iterkeys():
        dict2Keys.append(key2)
    return sameItemInBothLists(dict1Keys,dict2Keys)
    

def subtractFromList(toBeSubtracted,theList):
    indicesToBeRemoved = []
    for i in range(len(theList)):
        for j in range(len(toBeSubtracted)):
            if theList[i] == toBeSubtracted[j]:
                indicesToBeRemoved.append(i)
    resultingList = []
    for i in range(len(theList)):
        if not foundInList(i,indicesToBeRemoved):
            resultingList.append(theList[i])
    return resultingList
        
def findNextIndex(flagWithArgList, args):
    nextIndex = 2 #flags have been detected so initially select index right after flag argument(arg[2])
    for i in range(len(flagWithArgList)):
        if len(flagWithArgList[i]) > 1:
            nextIndex += 1
    return nextIndex
    
def concatFlagWithArgList(flagIndices, relOrder, args):
    argList = []
    errList = []
    for i in range(len(flagIndices)):
        if foundInTuplesList(flagIndices[i][0],relOrder):
            relOrderIndex = findIndexInTuplesList(flagIndices[i][0],relOrder)
            try:
                argList.append((flagIndices[i][0], args[2+relOrder[relOrderIndex][1]]))
            except IndexError: #this will occur when the amount of parameters provided is less than necessary
                errList.append("Insufficient number of parameters provided!") #TODO: look into this
        else:
            argList.append((flagIndices[i][0],))
    return argList,errList
            
    
def findIndexInTuplesList(item, list):
    for i in range(len(list)):
        if list[i][0] == item:
            return i
    return G.arbitraryIndexVal
    
#checks if item equals [(w, x), (y, z),...]
#                        ^       ^
def foundInTuplesList(item, list):
    for i in range(len(list)):
        if list[i][0] == item:
            return True
    return False

#initializes G.flagDict and G.flags and returns a boolean value
#representing if any duplicate flags were found
def makeFlagDict(argv):
    
    G.flags = argv[1][1:] #TODO: use retreveFlagsAndParams() here
    for i in range(len(G.flags)):
        try: #retrieving established flag index value
            garbageVal = G.flagDict[G.flags[i]]
            return True #duplicate flags found
        except: #create new dictionary entry
            G.flagDict[G.flags[i]] = i
    return False #duplicate flags not found

def determineFlagsPresent(allFlags):
    orderMatters = allFlags
    delList = []
    for i in range(len(orderMatters)):
        try:
            temp = G.flagDict[orderMatters[i]]
        except:
            delList.append(i)
    #for i in range(len(delList)): 
    #    orderMatters = delItemInList(delList[i],orderMatters)
    #TODO: make the following block a function as I have this portion of code twice in this file already
    resultingList = []
    for i in range(len(orderMatters)):
        if not foundInList(i,delList):
            resultingList.append(orderMatters[i])
    return resultingList

def findRelativeOrder(listOfIndicies):
    relativeOrder = []
    for i in range(len(listOfIndicies)):
        relativeOrder.append((listOfIndicies[i][0],i))
    return relativeOrder   

def retrieveFromDict(key):
    try:
        return G.flagDict[key]
    except:
        return G.arbitraryIndexValue
    
def delItemInList(item,l):
    for i in range(len(l)):
        if l[i] == item:
            del l[i]
            return l
    return l

#TODO: implement this method properly
def findFlagWithParamIndices(allFlags,argv):
    orderMatters = determineFlagsPresent(allFlags)
    if len(orderMatters) < 2:
        for i in range(len(argv[1])):
            if orderMatters == []:
                return []
            elif argv[1][i] == orderMatters[0]:
                return [(orderMatters[0], G.flagDict[orderMatters[0]])]
        return []
    else:
        orderedList = []
        for i in range(len(orderMatters)):
            if i == 0: #we know there will be at least one valid entry...
                orderedList.append((orderMatters[i],retrieveFromDict(orderMatters[i])))
            else: #for more than one entry
                for j in range(len(orderedList)): #insert tuple (flag, index) in proper order in list
                    if G.flagDict[orderMatters[i]] < orderedList[j][1]:
                        try:
                            while G.flagDict[orderMatters[i]] < orderedList[j-1][1]:                                
                                j-=1
                        except:
                            pass
                        orderedList.insert(j, (orderMatters[i],G.flagDict[orderMatters[i]]))
                        break
                    elif G.flagDict[orderMatters[i]] > orderedList[j][1]:
                        try:
                            while G.flagDict[orderMatters[i]] > orderedList[j+1][1]:                                
                                j+=1
                        except:
                            pass
                        orderedList.insert(j+1, (orderMatters[i],G.flagDict[orderMatters[i]]))
                        break
        return orderedList
  
#returns list of tuples in this format: (flag, index) ordered in the same order they were specified
#in the flag argument (i.e. '-ped' = [('p',0),('e',1),('d',2)] )
def findFlagIndices(allFlags,argv):
    orderMatters = determineFlagsPresent(allFlags)
    if len(orderMatters) < 2:
        for i in range(len(argv[1])):
            if orderMatters == []:
                return []
            elif argv[1][i] == orderMatters[0]:
                return [(orderMatters[0], G.flagDict[orderMatters[0]])]
        return []
    else:
        orderedList = []
        for i in range(len(orderMatters)):
            if i == 0: #we know there will be at least one valid entry...
                orderedList.append((orderMatters[i],retrieveFromDict(orderMatters[i])))
            else: #for more than one entry
                for j in range(len(orderedList)): #insert tuple (flag, index) in proper order in list
                    if G.flagDict[orderMatters[i]] < orderedList[j][1]:
                        try:
                            while G.flagDict[orderMatters[i]] < orderedList[j-1][1]:                                
                                j-=1
                        except:
                            pass
                        orderedList.insert(j, (orderMatters[i],G.flagDict[orderMatters[i]]))
                        break
                    elif G.flagDict[orderMatters[i]] > orderedList[j][1]:
                        try:
                            while G.flagDict[orderMatters[i]] > orderedList[j+1][1]:                                
                                j+=1
                        except:
                            pass
                        orderedList.insert(j+1, (orderMatters[i],G.flagDict[orderMatters[i]]))
                        break
        return orderedList

def flagFound(item,allFlags):
    for i in range(len(allFlags)):
        if allFlags[i] == item:
            return True
    return False

#TODO:Get rid of this method?
#returns list of all illegal flags
def checkForIllegalFlags(allFlags):
    illegalFlags = []
    for i in range(len(G.flags)):
        if not flagFound(G.flags[i],allFlags):
            illegalFlags.append(G.flags[i])
    return illegalFlags
    
#checks if hyphen present, if so assume flags are specified within the same argument
def checkForFlags(argv):
    try:
        if argv[1][0] == '-':
            return True
        else:
            return False
    except IndexError:
        return False    
    
def extractIPAddr(ipAddrFromLog):
    return ipAddrFromLog[1:-2]

def extractPort(portFromLog):
    port = []
    purePortNum = portFromLog[1:-1]
    for i in range(len(purePortNum)):
        if purePortNum[i] != '0':
            return purePortNum[i:]
            #port.append(purePortNum[i])
    #return ''.join(port)
    return '0'

#DEPRECIATED - DO NOT USE/ENHANCE
#OLD DESCRIPTION:
#This module returns a tuple with 4 values, the first one is a list of tuples with the flag letter
#and that flag's index for all flags that were found in argv[1], the second one returns a tuple of
#flags with their indices relative to other order-dependent flags, the third element returns any
#flags that weren't present in the allFlags list, and the fourth returns a boolean value depending
#on if a hypen(-) was found, to determine if flags were entered or not.
def getFlagList(allFlags,orderedFlags,argv):
    illegalFlags =[]
    if checkForFlags(argv):
        makeFlagDict(argv)
        illegalFlags = checkForIllegalFlags(allFlags)
        flagIndices = findFlagIndices(allFlags,argv)
        relOrder = findRelativeOrder(findFlagIndices(orderedFlags,argv))
        return (flagIndices,relOrder,illegalFlags,True)
    else:
        return ([],[],[],False)
    
#for debugging purposes in eclipse
if __name__ == '__main__':
    fC = flagConstraints({'d':['d']},{'s':['f','filter'],'scramble':['f','filter']})
    pC = paramConstraints({'s':['f','u','i','v'],'scramble':['f','u','i','v'],'f':['i','u','p','d'],\
                                       'filter':['i','u','p','d']},True,['p','parse'],{ 's':( {} , {'u':['v']} ),\
                                                                               'scramble':( {} , {'u':['v']} ) })
    fM = flagManager(['p','parse','f','filter','d','F','s','scramble'],['p','parse','f','filter','s','scramble'],\
                     ['FLA.py','--parse=-300','--scramble=fu','../../../../Programming/Projects/FLA/LOGS/fzs-2009-04-23.log'],pC,fC)
    print fM.getNextIndex()
    #flghndle = flagManager(['p','i','u','f','d','F'],['p','d','f'],['FlA', '-pdf', 'path', 'directory','f'])


    