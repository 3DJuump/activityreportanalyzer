#!/usr/bin/env python 

## DEPENDENCIES
import json
import sys
import zipfile
import os
import tempfile
import shutil
import subprocess
import datetime
import collections
import copy
import time

	
########################################
#
# due to network errors, proxy messages could be duplicated
# this class will remove duplicates that could lead to interpretation errors
#
########################################
class ProxyEntryFilter:
	def __init__(self):
		self.__mInfoPerProxy = {}
		
	def filterMessage(self, pJson):
		lProxyId = pJson['proxyid']
		lType = pJson['type'] if 'type' in pJson else ''
		lTs = pJson['ts'] if 'ts' in pJson else ''
		if not lProxyId in self.__mInfoPerProxy:
			self.__mInfoPerProxy[lProxyId] = {}
		if lType == 'StartProxyService' or lType == 'StopProxyService':
			if lType in self.__mInfoPerProxy[lProxyId] and self.__mInfoPerProxy[lProxyId][lType] == lTs:
				return None
			self.__mInfoPerProxy[lProxyId][lType] = lTs
		return pJson
				
########################################
#
# structure used to count occurences
#
########################################
class OccurenceCounter:
	def __init__(self):
		self.mData = {}
		
	def addOccurence(self, pOccurence):
		if not pOccurence in self.mData:
			self.mData[pOccurence] = 0
		self.mData[pOccurence] = self.mData[pOccurence] + 1

########################################
#
# this object will extract directory and data session from an activity report
#
########################################
class SessionAggregator:
	def __init__(self, pReportValidatorExe, pZipFile, pIgnoreValidityCheck):
		self.__mReportValidatorExe = None
		self.__mTmpFolder = None
		self.__mDirectorySessions = {}
		self.__mDirectorySessionsWithDuplicatedIds = []
		self.__mDataSessions = {}
		self.__mBorrowChanges = []
		
		
		# create a temporary folder
		self.__mTmpFolder = tempfile.mkdtemp()
		# print('Extract zip in temporary folder ' + self.__mTmpFolder)
		lZipFile = zipfile.ZipFile(pZipFile, 'r')
		lZipFile.extractall(self.__mTmpFolder)
		
		# look for activity report
		self.__mActivityReport = None
		for lFile in os.listdir(self.__mTmpFolder):
			if lFile.startswith('activity_report_') and lFile.endswith('.txt'):
				if self.__mActivityReport != None:
					raise Exception('found several activity report in zip file !')
				self.__mActivityReport = os.path.join(self.__mTmpFolder,lFile)
		if self.__mActivityReport is None:
			raise Exception('activity report is missing from zip')
		
		if not pIgnoreValidityCheck:
			if pReportValidatorExe is None or not os.path.isfile(pReportValidatorExe):
				raise Exception('Fail to locate validator tool')
			lCallRes = subprocess.call([pReportValidatorExe,self.__mActivityReport])
			if lCallRes != 0:
				print('\n/!\\#/!\\#/!\\#/!\\#/!\\#/!\\')
				print('Activity report WAS ALTERED')
				print('/!\\#/!\\#/!\\#/!\\#/!\\#/!\\\n')
				raise Exception('Fail to validate activity report')
		
	def __del__(self):
		
		if not self.__mTmpFolder is None:
			# print('remove temporary folder ' + self.__mTmpFolder)
			shutil.rmtree(self.__mTmpFolder)
			
	def __ts_extractor(self,a):
		return a['ts']
	
	def __get_ts_of_session(self,e):
		if 'startts' in e:
			return e['startts']
		elif 'lastclientcontact' in e:
			return e['lastclientcontact']
		else:
			return 0
			
	def __editDirectorySession(self, pJson):
		if not 'sessionid' in pJson:
			print('ignore directory session event (no sessionid) %s' % (pJson))
			return None
		lSessionId = pJson['sessionid']
		
		if not lSessionId in self.__mDirectorySessions:
			lSession = {
				'type':'directorysession',
				'sessionid' : lSessionId,
				'errors':[],
				'actions':[],
				'wasauthenticated':False,
				'native':None,
				'datasessioncount':0
			}
			self.__mDirectorySessions[lSessionId] = lSession
		lSession = self.__mDirectorySessions[lSessionId]
		# update informations fields
		for f in ['native','SSO','SSO_info','client@','claims','oidcsub','redirecturi']:
			if f in  pJson:
				lSession[f] = pJson[f]
		if 'lastclientcontact' in pJson:
			if 'lastclientcontact' in lSession:
				lSession['lastclientcontact'] = max(lSession['lastclientcontact'],pJson['lastclientcontact'])
			else:
				lSession['lastclientcontact'] = pJson['lastclientcontact']
		
		lType = pJson['type'] if 'type' in pJson else None
		lResult = pJson['result'] if 'result' in pJson else None
		if lResult is not None and lResult != 'E_No_Error':
			lSession['errors'].append('(%s %s) ' % (lType,lResult))
		lSession['actions'].append(lType)
		
		return lSession
	
	def __editDataSession(self, pJson):
		if not 'sessionid' in pJson:
			print('ignore data session event (no sessionid) %s' % (pJson))
			return None
		lSessionId = pJson['sessionid']
		if not lSessionId in self.__mDataSessions:
			lSession = {
				'type':'datasession',
				'sessionid' : lSessionId,
				'errors':[],
				'actions':[],
				'isvalid':False
			}
			self.__mDataSessions[lSessionId] = lSession
		lSession = self.__mDataSessions[lSessionId]
		# update informations fields
		for f in ['proxyurl','oidcsub','directorysessionid','native','openinfo','locallmxfeature']:
			if f in pJson:
				lSession[f] = pJson[f]
		if 'lastclientcontact' in pJson:
			if 'lastclientcontact' in lSession:
				lSession['lastclientcontact'] = max(lSession['lastclientcontact'],pJson['lastclientcontact'])
			else:
				lSession['lastclientcontact'] = pJson['lastclientcontact']
		
		
		lType = pJson['type'] if 'type' in pJson else None
		lResult = pJson['result'] if 'result' in pJson else None
		if lResult is not None and lResult != 'E_No_Error':
			lSession['errors'].append('(%s %s) ' % (lType,lResult))
		lSession['actions'].append(lType)
		return lSession
	
	def __closePendingDirectorySession(self, pReason, pTs, pSession):
		if not 'revokeinfo' in pSession:
			pSession['revokeinfo'] = pReason
		if not 'endts' in pSession:
			pSession['endts'] = pTs
	
	def __closePendingDirectorySessions(self, pReason, pTs):
		for k in self.__mDirectorySessions:
			lSession = self.__mDirectorySessions[k]
			self.__closePendingDirectorySession(pReason,pTs,lSession)
			
	def __closePendingDataSessions(self, pReason, pTs, pProxyId):
		for k in self.__mDataSessions:
			lSession = self.__mDataSessions[k]
			
			if pProxyId is not None:
				if not pProxyId == lSession['proxyid'] :
					continue
			if not 'revokeinfo' in lSession:
				lSession['revokeinfo'] = pReason
			if not 'endts' in lSession:
				lSession['endts'] = pTs
	
	def __patchSessions(self, pSessions, pStats):
		
		for k in pSessions:
			lEntry = pSessions[k]
			
			if 'startts' in lEntry:
				if not 'lastclientcontact' in lEntry:
					# if lastclientcontact is missing set it to startts
					lEntry['lastclientcontact'] = lEntry['startts']
				else:
					# sometimes lastclientcontact could be smaller than startts because log entry is generated after session creation
					lEntry['lastclientcontact'] = max(lEntry['lastclientcontact'],lEntry['startts'])
			
			# if there is an error set endts and lastclientcontact to startts
			if 'errors' in lEntry and len(lEntry['errors']):
				if 'revokeinfo' in lEntry:
					lEntry['revokeinfo'] = 'error'
			
			if lEntry['type'] == 'datasession' or lEntry['type'] == 'directorysession':
				lStat = pStats[lEntry['type']]
				lStat['total'] = lStat['total'] + 1
				
				if 'revokeinfo' in lEntry:
					lRevokeInfo = lEntry['revokeinfo']
					if not lRevokeInfo in lStat['revokeinfo']:
						lStat['revokeinfo'][lRevokeInfo] = 0
					lStat['revokeinfo'][lRevokeInfo] = lStat['revokeinfo'][lRevokeInfo] + 1
			
				if 'native' in lEntry and lEntry['native']:
					lStat['native'] = lStat['native'] + 1
				if 'SSO' in lEntry and lEntry['SSO']:
					lStat['sso'] = lStat['sso'] + 1	
	
	def getHeader(self):
		if self.__mActivityReport is None:
			raise Exception('Invalid activity report')
		
		lRes = {}
		
		with open(self.__mActivityReport) as lF:
			for r in lF:
				if not r.startswith('#'):
					lRes['firstentry'] = json.loads(r)
					break
				# a comment, print it
				if r.startswith('# LMX feature : '):
					lRes['LMX_feature'] = r[16:].strip()
				elif r.startswith('# License ID : '):
					lRes['License_ID'] = r[15:].strip()
				elif r.startswith('# Period : '):
					lSplitRes = r[11:].split(' to ')
					lRes['Period_start'] = lSplitRes[0].strip()
					lRes['Period_end'] = lSplitRes[1].strip()
		return lRes
		
	def parseReport(self):
		import re
		if self.__mActivityReport is None:
			raise Exception('Invalid activity report')
		
		lBorrowEntries = []
		
		lEntriesPerType = OccurenceCounter()
		lRedirectUris = OccurenceCounter()
		lDataSessionOidcSubs = OccurenceCounter()
		lDataSessionProxyIds = OccurenceCounter()
		
		lRemoveSignInfoRe = re.compile('("chainid":[0-9]+,?|"chainsign":"\S+?",?)')
		
		lAllUniqueEvent = set()
		lLastTs = {}
		lMaxTs = 0
		lMinTs = sys.maxsize
		lProxyMsgFiler = ProxyEntryFilter()
		lLmxFeature = None
		with open(self.__mActivityReport) as lF:
			lRowCptr = 0
			for r in lF:
				lRowCptr = lRowCptr + 1
				r = r.strip()
				if r.startswith('#'):
					# a comment, print it
					if r.startswith('# LMX feature : '):
						lLmxFeature = r[16:].strip()
					continue
				try:
				
					# in some rare case an event could be duplicated (posted twice by a proxy if it does not receive ack)
					# here we remove them
					lUniqueKey = lRemoveSignInfoRe.sub('',r)
					if lUniqueKey in lAllUniqueEvent:
						# duplicated event skip it
						continue
					lAllUniqueEvent.add(lUniqueKey)
					
					lJson = json.loads(r)
					lType = lJson['type'] if 'type' in lJson else ''
					lTs = lJson['ts']
					lMaxTs = lTs if lMaxTs < lTs else lMaxTs
					lMinTs = lTs if lMinTs > lTs else lMinTs
					
					lEntriesPerType.addOccurence(lType)
					
					
					## DIRECTORY SESSION
					if lType == 'DirectoryApiStatus':
						if lJson['lmxinfo'] != None:
							lBorrowEntries.append(lJson)
					#if lType == 'StartDirectoryService':
					#	self.__closePendingDirectorySessions('service start without close',lTs)
					#elif lType == 'StopDirectoryService':
					#	self.__closePendingDirectorySessions('service stop',lTs)
					#elif lType == 'DirectoryServiceStatus':
					#	lBorrowEntries.append(lJson)
					#elif lType == 'BorrowLicenseCheckOut':
					#	#ignore
					#	pass
					#elif lType == 'BorrowLicenseCheckIn':
					#	#ignore
					#	pass
					#elif lType == 'BorrowLicenseRenew':
					#	#ignore
					#	pass
					elif lType == 'RequestDirectorySessionAuth':
						
						lResult = lJson['result'] if 'result' in lJson else ''
						lSessionId = lJson['sessionid']
						if lSessionId in self.__mDirectorySessions and lResult == 'E_No_Error':
							# sometimes a directory session id is reused by client
							# if previous session still exists it leads to an error else we will have two sessions with same id in the report and we need to deal with it for now
							print('/!\\ Found directorysession with reused id "%s", type %s' % (lSessionId, 'native' if lJson['native'] else 'web'))
							lPreviousSession = copy.deepcopy(self.__mDirectorySessions[lSessionId])
							self.__closePendingDirectorySession('sessionid reused',lJson['ts'],lPreviousSession);
							self.__mDirectorySessionsWithDuplicatedIds.append(lPreviousSession)
							del self.__mDirectorySessions[lSessionId]
					
						lSession = self.__editDirectorySession(lJson)
						if lSession is not None and lResult == 'E_No_Error':
							if 'startts' in lSession:
								raise Exception('this directory session was already created')
							lSession['startts'] = lTs
							lRedirectUris.addOccurence(lJson['redirecturi'])
							
					elif lType == 'RequestDirectorySessionAuthBis' or lType == 'RequestRegisterFrontEndUser':
						lSession = self.__editDirectorySession(lJson)
						if lType == 'RequestRegisterFrontEndUser':
							lSession['isregisterfrontenduser'] = True
							if 'startts' in lSession:
								raise Exception('this directory session was already created')
							lSession['startts'] = lTs
							
					elif lType == 'DirectorySessionAuthenticated' or lType == 'FrontEndUserRegistered':
						lSession = self.__editDirectorySession(lJson)
						if lType == 'FrontEndUserRegistered':
							lSession['isregisterfrontenduser'] = True
						lResult = lJson['result'] if 'result' in lJson else ''
						if not lSession is None and lResult == 'E_No_Error':
							lSession['wasauthenticated'] = True
							
					#elif lType == 'CloseInfiniteSession':
					#	lSession = self.__editDirectorySession(lJson)
					#	lResult = lJson['result'] if 'result' in lJson else ''
					#	if not lSession is None and lResult == 'E_No_Error':
					#		lSession['endts'] = lTs
					elif lType == 'DestroyDirectorySession':
						lSession = self.__editDirectorySession(lJson)
						if not lSession is None:
							if not 'endts' in lSession:
								lSession['endts'] = lTs
							lSession['revokeinfo'] = lJson['reason'] if 'reason' in lJson else 'unknown'
					## DATA SESSION
					#elif 'proxyid' in lJson:
					#	lJson = lProxyMsgFiler.filterMessage(lJson)
					#	if lJson is None:
					#		continue
					#	if lType == 'StartProxyService':
					#		if 'proxyid' in lJson:
					#			self.__closePendingDataSessions('service start without close',lTs,lJson['proxyid'])
					#	elif lType == 'StopProxyService':
					#		if 'proxyid' in lJson:
					#			self.__closePendingDataSessions('service stop',lTs,lJson['proxyid'])
					elif lType == 'OpenDataSession':
						
						if not 'oidcsub' in lJson:
							if lJson['result'] != 'E_Missing_404':
								raise Exception('missing oidcsub')
						else:
							lDataSessionOidcSubs.addOccurence(lJson['oidcsub'])
						if 'proxyurl' in lJson:
							lDataSessionProxyIds.addOccurence(lJson['proxyurl'])
						
						lSession = self.__editDataSession(lJson)
						if 'startts' in lSession and lSession['startts'] != lTs:
							raise Exception('this data session was already created')
						lDirectorySessionId = lJson['directorysessionid']
						if lDirectorySessionId in self.__mDirectorySessions:
							self.__mDirectorySessions[lDirectorySessionId]['datasessioncount'] = self.__mDirectorySessions[lDirectorySessionId]['datasessioncount'] + 1
						lResult = lJson['result'] if 'result' in lJson else ''
						if lResult == 'E_No_Error':
							lSession['isvalid'] = True
						lSession['startts'] = lTs
						
					elif lType == 'DestroyDataSession':
						lSession = self.__editDataSession(lJson)
						if not lSession is None:
							lSession['revokeinfo'] = lJson['reason']
							lSession['endts'] = lTs
							
					#	elif lType == 'RevokeDataSession':
					#		lSession = self.__editDataSession(lJson)
					#		lSession['revokeinfo'] = lJson['revokeinfo']
					#		if not 'endts' in lSession:
					#			lSession['endts'] = lTs
					#	elif lType == 'DestroyPgRoles':
					#		for tmplogin in lJson['roles']:
					#			# look if this temporary role matches a session and tag it as revoked
					#			# this might appen if a proxy is shutted down without having time to report a StopDirectoryService
					#			lSession = self.__mDataSessionsTmpLoginIndex.get(tmplogin, None)
					#			if lSession is not None:
					#				if not 'revokeinfo' in lSession:
					#					lSession['revokeinfo'] = 'tmp role destroyed'
					#	elif lType == 'HeartbeatProxyService':
					#		pass
					#	else:
					#		print('unhandled proxy type %s @row %i' % (lType,lRowCptr))
					## ???
					else:
						print('unhandled type %s @row %i' % (lType,lRowCptr))
						raise Exception()
				except:
					raise Exception('fail to process row @%i %s' % (lRowCptr,r))
			self.__closePendingDirectorySessions('end of report',lMaxTs)
			self.__closePendingDataSessions('end of report',lMaxTs,None)
		
		# sort borrow entries per ts
		lBorrowEntries.sort(key=self.__ts_extractor)
		lBorrowCount = -1
		# analyze borrow
		for lJson in lBorrowEntries:
			lType = lJson['type']
			if lBorrowCount != lJson['lmxinfo']['lmxborrowedlic']:
				# init borrow counter with offset read from lmx server
				lBorrowCount = lJson['lmxinfo']['lmxborrowedlic']
				self.__mBorrowChanges.append({'type':'borrowcountchange','borrowedlic':lBorrowCount,'ts':lJson['ts'],'tsstr':str(datetime.datetime.fromtimestamp(lJson['ts']))})
		
		lStats = {
			'type':'stats',
			'types':{},
			'uris':{},
			'datasession':{
				'oidcsubs':{},
				'proxyids':{},
				'native':0,
				'total':0,
				'revokeinfo':{}
			},
			'directorysession':{
				'native':0,
				'sso':0,
				'total':0,
				'revokeinfo':{}
			},
			'lmx_feature':lLmxFeature
		}
		self.__patchSessions(self.__mDirectorySessions,lStats)
		self.__patchSessions(self.__mDataSessions,lStats)

		lStats['types'] = lEntriesPerType.mData
		
		lStats['uris'] = lRedirectUris.mData
			
		lStats['datasession']['oidcsubs'] = lDataSessionOidcSubs.mData
			
		lStats['datasession']['proxyids'] = lDataSessionProxyIds.mData
		
		lDirectorySessionList =list(self.__mDirectorySessions.values()) 
		lDirectorySessionList.sort(key=self.__get_ts_of_session)
		lDataSessionList = list(self.__mDataSessions.values())
		lDataSessionList.sort(key=self.__get_ts_of_session)
		
		return lDirectorySessionList + lDataSessionList + self.__mBorrowChanges + [lStats]

########################################
#
# helper used to save list of json objects into a csv file
#
########################################
def jsonObjectListToCsv(pObjects, pPreferedColumnOrder, pColumnToSetAtEnd, pFile, pCsvDelimiter):
	import csv
	lColumnsDict = {}
	lFirstColumnsArray = []
	lLastColumnsArray = []
	
	for c in pPreferedColumnOrder:
		if c in lColumnsDict:
			continue
		lColumnsDict[c] = 0
		lFirstColumnsArray.append(c)
	for c in pColumnToSetAtEnd:
		if c in lColumnsDict:
			continue
		lColumnsDict[c] = 0
		lLastColumnsArray.append(c)
	
	lOtherColumnsArray = []
	# iterate over all objects to find columns name
	for o in pObjects:
		for k in o:
			if k in lColumnsDict:
				continue
			lColumnsDict[k] = 0
			lOtherColumnsArray.append(k)
	lOtherColumnsArray.sort()
	lColumnsArray = lFirstColumnsArray + lOtherColumnsArray + lLastColumnsArray
	for i in range(0,len(lColumnsArray)):
		lColumnsDict[lColumnsArray[i]] = i
	
	with open(pFile,'w', newline='') as f:
		writer = csv.writer(f,delimiter=pCsvDelimiter,quotechar='"')
		writer.writerow(lColumnsArray)
		for o in pObjects:
			lVals = ['']*len(lColumnsArray)
			for k in o:
				lVals[lColumnsDict[k]] = o[k]
			writer.writerow(lVals)
			
########################################
#
# helper used to convert ts (second since UTC epoch ) into string
#
########################################
def addStrVersionOfTsFields(pEntries, pTsFields):
	for e in pEntries:
		for sk in pTsFields:
			if sk in e:
				e[sk + 'str'] = str(datetime.datetime.fromtimestamp(e[sk]))

########################################
#
# this class fill select only valid datasession and borrow informations, it will then output those informations as a new change log in csv ordered by ts
#
########################################
class ExtractBillingInformations:
	def __init__(self, pOutput, pCsvFr, pOutputActiveSessions):
		self.__mOutput = pOutput
		self.__mPreviousBorrowCount = 0
		self.__mCsvDelimiter = ';' if pCsvFr else ','
		self.__mOutputActiveSessions = pOutputActiveSessions
	
	def __get_sort_criteria(self,e):
		return (e['ts'],-e['lic_count_delta'])
		
	def processEntries(self, pEntries):
		lDirectorySessions = {}
		for e in pEntries:
			if e['type'] != 'directorysession':
				continue
			lDirectorySessions[e['sessionid']] = e
		lNewEntries = []
		lLmxFeature = 'n/a'
		for e in pEntries:
			lNewEntry = None
			if e['type'] == 'borrowcountchange':
				lBorrowCount = e['borrowedlic']
				if lBorrowCount == self.__mPreviousBorrowCount:
					continue
				lNewEntry = {
					'ts' : e['ts'],
					'type':'borrowchange',
					'lic_count_delta': lBorrowCount - self.__mPreviousBorrowCount,
				}
				lNewEntries.append(lNewEntry)
				self.__mPreviousBorrowCount = lBorrowCount
				
			elif e['type'] == 'datasession':
				if not e['isvalid']:
					continue
				lStartTs = e['startts']
				lEndTs = None
				lEndTsIsLastClientContact = True
				if e['revokeinfo'].lower() in ['close by application','directory session was removed','revoked by admin','end of life','user was removed or disabled'] : # 'Close by application','Revoked by the directory','revoked by proxy event','Lost directory connection','end of life','pg_role was destroyed','Service is about to exit'
					lEndTs = e['endts']
					lEndTsIsLastClientContact = False
				elif e['revokeinfo'].lower() in ['no heartbeat','proxy was removed','corrupted db','not authenticated on time','proxy is no more available','build is no more available']: # 'No heartbeat received','service start without close','end of report','tmp role destroyed'
					lEndTs = e['lastclientcontact']
				else:
					raise Exception('unhandled revoke info "%s" %s' % (e['revokeinfo'],e) )
				
				# retrieve directory sessionid
				if not e['directorysessionid'] in lDirectorySessions:
					print('/!\\ Data session reference an unknown directory session "%s", type %s, oidcsub "%s"' % (e['directorysessionid'], 'native' if e['native'] else 'web', e['oidcsub'] if 'oidcsub' in e  else 'n/a' ))
				
				
				# here do not use copy.deepcopy(e) it is really slow
				lStartEntry = {}
				for k in ['revokeinfo','directorysessionid','errors','isvalid','native','sessionid','type','oidcsub']:
					lStartEntry[k] = e[k]
				lHasLic = False
				if 'locallmxfeature' in e:
					lHasLic = True
					lStartEntry['locallmxfeature'] = e['locallmxfeature']
				
				lStartEntry['ts'] = lStartTs
				lStartEntry['lic_count_delta'] = 0 if lHasLic else 1
				lStartEntry['endts'] = lEndTs
				lStartEntry['endtsislastclientcontact'] = lEndTsIsLastClientContact
				lNewEntries.append(lStartEntry)
				
				lEndEntry = {
					'ts':lEndTs,
					'type':'datasession',
					'sessionid':e['sessionid'],
					'lic_count_delta':0 if lHasLic else -1
				}
				lNewEntries.append(lEndEntry)
			elif e['type'] == 'stats':
				lLmxFeature = e['lmx_feature']
			else:
				continue
		# sort entries by id (currently ts) and renumber id
		lNewEntries.sort(key=self.__get_sort_criteria)
		for e in lNewEntries:
			e['lmx_feature'] = lLmxFeature
		
		# compute cumulated fields
		# and generate real id
		lId = 1
		lAllLicCountSum = 0
		lBorrowCountSum = 0
		lActiveSessions = set()
		for e in lNewEntries:
			lAllLicCountSum = lAllLicCountSum + e['lic_count_delta']
			if lAllLicCountSum < 0:
				raise Exception('Got a negative lic count !!')
			if e['type'] == 'borrowchange':
				lBorrowCountSum = lBorrowCountSum + e['lic_count_delta']
				if lBorrowCountSum < 0:
					raise Exception('Got a negative borrow lic count !!')
			else:
				lSessionId = e['sessionid']
				if e['lic_count_delta'] < 0:
					if not e['sessionid'] in lActiveSessions:
						raise Exception('Session close inconsistency')
					lActiveSessions.remove(lSessionId)
				elif e['lic_count_delta'] > 0:
					if e['sessionid'] in lActiveSessions:
						raise Exception('Session open inconsistency')
					lActiveSessions.add(lSessionId)
						
			e['id'] = lId
			e['all_lic_count_cumulated'] = lAllLicCountSum
			e['only_borrow_count_cumulated'] = lBorrowCountSum
			if self.__mOutputActiveSessions:
				lTmpList = list(lActiveSessions)
				lTmpList.sort()
				e['activesessions'] = lTmpList
			lId = lId + 1
			
		addStrVersionOfTsFields(lNewEntries,['ts','startts','endts'])
		with open('out.json','w') as f:
			json.dump(lNewEntries,f,sort_keys=True,indent=4)
		jsonObjectListToCsv(lNewEntries,['id','tsstr','type','endtsstr','revokeinfo','lic_count_delta','all_lic_count_cumulated','only_borrow_count_cumulated'],['lmx_feature'] + ['activesessions'] if self.__mOutputActiveSessions else [],self.__mOutput,self.__mCsvDelimiter)
		
def retrieveArgOpt(pArgs, pOpt):
	if not pOpt in pArgs:
		return False
	pArgs.remove(pOpt)
	return True
	
def retrieveArgVal(pArgs, pKey):
	if not pKey in pArgs:
		return None
	lIndex = pArgs.index(pKey)
	if lIndex + 1 >= len(pArgs):
		raise Exception('need a value after %s' % (pKey))
	lRes = pArgs[lIndex+1]
	del pArgs[lIndex:lIndex+2]
	return lRes
		
## MAIN
if __name__ == '__main__':
	
	lArgsWithoutOpt = sys.argv
	# retrieve options
	lIgnoreValidityCheck = retrieveArgOpt(lArgsWithoutOpt,'-ignorevaliditycheck')
	lCsvFr = retrieveArgOpt(lArgsWithoutOpt,'-csvfr')
	lExtended = retrieveArgOpt(lArgsWithoutOpt,'-extended')
	lOutputBaseFolder = retrieveArgVal(lArgsWithoutOpt,'-o')
	lForceReprocessing = retrieveArgOpt(lArgsWithoutOpt,'-force')
	lNoIntermediateResult = retrieveArgOpt(lArgsWithoutOpt,'-nointermediateresult')
	
	if len(lArgsWithoutOpt) != 2:
		print('Usage script.py report.zip|folder [-ignorevaliditycheck] [-csvfr] [-extended] [-force] [-nointermediateresult] [-o outputfolder]')
		print('-ignorevaliditycheck : will disable report signature check')
		print('-csvfr : will generate a csv with '';'' separator')
		print('-extended : will add an extra colum in csv containing ids of active sessions')
		print('-force : force reprocessing of all files')
		print('-nointermediateresult : if set only billing informations will be generated')
		print('-o : set output folder, if not specified output will in the same folder as input')
		raise Exception()
	lInputPathOrFile = lArgsWithoutOpt[1]
	
	lFilesToProcess = []
	
	lValidateActivityReportExePath = None
	for p in ['./bin','../../GENERATED/DELIVERY/MSVC16_x64/Tool_ValidateActivityReport/bin']:
		lPathToTest = os.path.join(p,'Tool_ValidateActivityReport.exe')
		if os.path.isfile(lPathToTest):
			lValidateActivityReportExePath = lPathToTest
			break
	lInputBasePath = None
	if os.path.isfile(lInputPathOrFile):
		lFilesToProcess.append(os.path.abspath(lInputPathOrFile))
		lInputBasePath = os.path.dirname(os.path.abspath(lInputPathOrFile))
	elif os.path.isdir(lInputPathOrFile):
		lInputBasePath = os.path.abspath(lInputPathOrFile)
		for root, dirs, files in os.walk(lInputBasePath):
			for f in files:
				if os.path.splitext(os.path.basename(f))[1] == '.zip':
					lFilesToProcess.append(os.path.join(root,f))
	else:
		raise Exception('invalid input path or file')
	if lOutputBaseFolder is None:
		lOutputBaseFolder = lInputBasePath
	lOutputBaseFolder = os.path.abspath(lOutputBaseFolder)
	
	if lIgnoreValidityCheck:
		print('/!\\/!\\/!\\/!\\')
		print('Activity report was DISABLED')
		print('/!\\/!\\/!\\/!\\')
	
	for lInput in lFilesToProcess:
		# compute path from root input
		lOutputFolder = os.path.join(lOutputBaseFolder,os.path.relpath(os.path.dirname(lInput),lInputBasePath))
		try:
			os.makedirs(lOutputFolder)
		except:
			pass
		
		lSessionAggregator = SessionAggregator(lValidateActivityReportExePath,lInput,lIgnoreValidityCheck)
		lReportInformations = lSessionAggregator.getHeader();
		
		lBaseName = lReportInformations['Period_end'] + '_' + lReportInformations['Period_start']
		if 'License_ID' in lReportInformations:
			lBaseName = lReportInformations['License_ID'] + '_' + lBaseName
		print(lBaseName)
		lOutputRawFile = os.path.join(lOutputFolder,lBaseName + '_sessions_raw_output.json')
		lCsvFile = os.path.join(lOutputFolder,lBaseName + '_billing_informations.csv')
		if not lForceReprocessing and (os.path.isfile(lOutputRawFile) or lNoIntermediateResult) and os.path.isfile(lCsvFile):
			print('skip\n\t%s\n\t%s' % (lInput,lCsvFile))
			continue
		print('process %s' %(lInput))
		
		lParseReportStartTs = time.time()
		lEntries = lSessionAggregator.parseReport()
		# print('parse report in %s' % (time.time() - lParseReportStartTs))
		
		if not lNoIntermediateResult:
			with open(lOutputRawFile,'w') as f:
				lDumpJsonStartTs = time.time()
				addStrVersionOfTsFields(lEntries,['startts','endts','lastclientcontact'])
				json.dump(lEntries,f,sort_keys=True,indent=4)
				# print('dump json in %s' % (time.time() - lDumpJsonStartTs))

		lExtractBillingInfoStartTs = time.time()
		lBillingInfoExtractor = ExtractBillingInformations(lCsvFile, lCsvFr,lExtended);
		lBillingInfoExtractor.processEntries(lEntries)
		# print('extract billing informations in %s' % (time.time() - lExtractBillingInfoStartTs))
		
	
	

	