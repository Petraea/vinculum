#!/usr/bin/python
from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import ReconnectingClientFactory
from os.path import exists, getmtime
from twisted.internet.task import LoopingCall

from twisted.internet import reactor
import re
import time
import logging

import os
mydir=os.path.dirname(os.path.realpath(__file__))
RULESFILE=mydir+os.sep+'vinculum.rules'
logging.basicConfig(filename=mydir+os.sep+'vinculum.log',level=logging.DEBUG)

DROPTIME = 999999

class Rule:
    '''This class is instantiated for each rule in the rulebook. It contains all the needed variables, included the compiled regex matcher for speed.'''
    def __init__(self,reactor,match,froms,dest,subfrom,subto,cont):
        self.reactor=reactor
        self.match='' or match
        self.mcompile=re.compile(match)
        self.froms='' or froms
        self.dest='' or dest
        self.ip=None
        self.cont=None or cont
        self.subfrom='' or subfrom
        self.subto='' or subto
        self.connection=None
        self.fromconnection=None
        self.type=''
        self.host=''
        self.dir=''
        self.port=''
        self.fromtype=''
        self.fromip=None
        self.fromdir=''
        self.fromhost=''
        self.fromport=''
        self.type,self.dir,self.host,self.port = self.parse_dest('to',self.dest)
        self.fromtype,self.fromdir,self.fromhost,self.fromport = self.parse_dest('from',self.froms)

    def __eq__(self, other):
        '''Compare rules based on their defining characteristics, not derived info.'''
        if type(other) != type(self): return False #Only match other rules.
        if self.match!=other.match: return False
        if self.froms!=other.froms: return False
        if self.dest!=other.dest: return False
        if self.subfrom!=other.subfrom: return False
        if self.subto!=other.subto: return False
        if self.cont!=other.cont: return False
        return True

    def __str__(self):
        ret = 'ma:'+str(self.match)
        ret = ret + ' mc:'+str(self.mcompile)
        ret = ret + ' fr:'+str(self.froms)
        ret = ret + ' dt:'+str(self.dest)
        ret = ret + ' sf:'+str(self.subfrom)
        ret = ret + ' st:'+str(self.subto)
        ret = ret + ' co:'+str(self.cont)
        ret = ret + ' ty:'+str(self.type)
        ret = ret + ' di:'+str(self.dir)
        ret = ret + ' ho:'+str(self.host)
        ret = ret + ' ip:'+str(self.ip)
        ret = ret + ' po:'+str(self.port)
        ret = ret + ' ty:'+str(self.fromtype)
        ret = ret + ' fd:'+str(self.fromdir)
        ret = ret + ' fh:'+str(self.fromhost)
        ret = ret + ' fi:'+str(self.fromip)
        ret = ret + ' fp:'+str(self.fromport)
        ret = ret + ' cn:'+str(self.connection)
        ret = ret + ' fc:'+str(self.fromconnection)
        return ret

    def got_dest_ip(self,addr):
        self.ip=addr

    def got_from_ip(self,addr):
        self.fromip=addr

    def parse_dest(self,version,dest):
        try:
            parts = dest.split(':')
            if len(parts) <3:
                type= 'TCP'
                dir= 'SEND'
                host = parts[0]
                port = int(parts[1])
            else:
                try:
                    type,dir = parts[0].split('-')
                    type=type.upper()
                    dir=dir.upper()
                    if dir != 'LISTEN': dir = 'SEND'
                except:
                    type = parts[0].upper()
                    dir= 'SEND'
                host = parts[1]
                port = int(parts[2])
            if version == 'from':
                if host in ['*','']: self.got_from_ip(None)
                else: self.reactor.resolve(host).addCallback(self.got_from_ip)
            elif version == 'to':
                if host in ['*','']: self.got_dest_ip(None)
                else: self.reactor.resolve(host).addCallback(self.got_dest_ip)
            return type, dir, host, port
        except Exception as e:
            logging.warning(e)
            return None, None, None, None

class Rules:
    '''This is the single class that contains all the rules. It is referenced by the reactor, and that is used to pass it through to the line reciever.'''
    def __init__(self,reactor):
        self.reactor=reactor
        self.rules=[]
        self.directory=[]
        self.rules_file=RULESFILE
        self.rules_last_read=0.0
        self.read_task = LoopingCall(self.read_rules)
        self.read_task.start(10, now=True)

    def parse_definition(self, text):
        '''Parse each line of the rulebook for what it represents.'''
        parts = ['']
        n = 0
        skip = False
        for l in text:
            if skip:
                if l != ',': #mis-skip
                    parts[n] = parts[n]+chr(92)+l
                else:
                    parts[n]+=l
                skip = False
                continue
            if l != ',':
                if l == chr(92): #Backslash!
                    skip = True
                    continue
                else:
                    parts[n]+=l
            else:
                n = n + 1
                parts.append('')
        parts = [x.strip() for x in parts]
        if parts[5] in ['True','true','T','1']: cont = True
        else: cont=False
        return Rule(self.reactor,parts[0],parts[1],parts[2],parts[3],parts[4],cont)

    def read_rules(self):
        '''On a timer loop, check the rules file for changes. If it's changed, update
        the working rules with new ones, only making the differences happen.'''
        if not exists(self.rules_file):
            self.rules=[]
            logging.error('No rules file present!')
            return
        try:
            mtime = getmtime(self.rules_file)
        except:
            return
        if mtime <= self.rules_last_read:
            return
        new_rules = []
        for line in open(self.rules_file):
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            rule = self.parse_definition(line)
            logging.warning('Adding rule '+str(rule))
            new_rules.append(rule)
        self.rules_last_read = mtime

        added = new_rules[:]
        lost = []
        sustained=[]
        for rule in self.rules:
            matched=False
            for nrule in new_rules:
#                if rule.match==nrule.match and rule.froms==nrule.froms and rule.dest==nrule.dest and rule.subfrom==nrule.subfrom and rule.subto==nrule.subto and rule.cont==nrule.cont:
                if rule != nrule:
                    sustained.append(rule)
                    added.remove(nrule)
                    matched=True
            if not matched:
                lost.append(rule)
        self.rules = new_rules[:]
        self.dropConnections(lost)
        self.raiseConnections(added)

    def dropConnections(self,lost):
        '''For all of the provided rules, if any of the connections don't exist anywhere else in the rulebook, drop the connection.'''
        deadconnections = set()
        for r in lost:
            if not any (r.connection == f.connection or r.connection == f.fromconnection for f in self.rules):
                deadconnections.add(r.connection)
            if not any (r.fromconnection == f.connection or r.fromconnection == f.fromconnection for f in self.rules):
                deadconnections.add(r.fromconnection)
        for c in deadconnections:
            try:
                c.transport.loseConnection()
                c.factory.stopTrying()
            except:
                pass

    def raiseConnections(self,new_rules):
        '''If the connection doesn't already exist in the rules, try and form a new connection from these rules,
        otherwise bind the old connection to the new rule.'''
        toraise = set((x.fromtype,x.fromdir,x.fromhost,x.fromport) for x in new_rules)
        toraise.update(set((x.type,x.dir,x.host,x.port) for x in new_rules))
        for type,dir,host,port in toraise:
            inDir=False
            for entry in self.directory:
                if entry.dir == 'LISTEN' and entry.type == type and entry._host.port == port:
                    entry.bind_rule()
                    inDir=True
                if entry.dir == 'SEND' and entry._host.host == host and entry.type == type and entry._host.port == port:
                    entry.bind_rule()
                    inDir=True
            if not inDir and dir == 'LISTEN':
                logging.warning('Listening on port: '+str(type)+':'+str(port))
                if type == 'TCP':
                    self.reactor.listenTCP(port, VinculumFactory(self.reactor))
                elif type == 'UDP':
                    self.reactor.listenUDP(port, VinculumFactory(self.reactor))
                elif type == 'SSL':
                    self.reactor.listenSSL(port, VinculumFactory(self.reactor))
                elif type == 'UNIX': #Using fromhost as unix socket address
                    self.reactor.listenUNIX(host, VinculumFactory(self.reactor))
            if not inDir and dir == 'SEND':
                if host is None: continue
                logging.warning('Connecting to: '+str(type)+':'+str(host)+':'+str(port))
                if type == 'TCP':
                    self.reactor.connectTCP(host,port,VinculumFactory(self.reactor))
#                elif type == 'UDP': #Yow!
                elif type == 'SSL':
                    self.reactor.connectSSL(host,port,VinculumFactory(self.reactor))
                elif type == 'UNIX':#Where host = filename
                    self.reactor.connectUNIX(host,VinculumFactory(self.reactor))

    def add_connection(self,connection):
        if connection not in self.directory:
            self.directory.append(connection)

    def del_connection(self,connection):
        if connection in self.directory:
            self.directory.remove(connection)

    def match(self,strn,dir,ip,port):
        '''Main workhorse function. Each new string sent in, match based on the entire rulebook based on IP, string, port.'''
        for rule in self.rules:
            if rule.fromip == ip or rule.fromip is None:
                if rule.fromport == port:
                    m = rule.mcompile.match(strn)
                    if m is not None:
                        logging.info('matched: '+str(rule.match)+' from '+str(ip))
                        line = strn
                        if rule.subfrom != '':
                            line = re.sub(rule.subfrom,rule.subto,strn)
                        if rule.connection:
                            try:
                                logging.info('sending: "'+line+'" to '+rule.dest)
                                rule.connection.sendLine(line)
                            except Exception as e:
                                logging.error('Sending line "'+str(line)+'" to '+rule.dest+' failed.')
                                logging.error(e)
                        if not rule.cont: break

class VinculumProtocol(LineReceiver):
    '''This is a custom Protocol that provides both Server and Client functionality in as many languages as possible.'''
    delimiter='\n'
    def __init__(self,reactor,factory):
        self.reactor=reactor
        self.factory=factory
        self.rules = reactor.rules
        self._peer = None
        self._host = None
        self.bound=False

    def connectionMade(self):
        self._peer = self.transport.getPeer()
        self._host = self.transport.getHost()
        self.type,dir=[x.upper() for x in str(type(self.transport))[8:-2].split('.')][2:]
        if dir == 'SERVER':self.dir='LISTEN'
        else: self.dir='SEND'
        self.rules.add_connection(self)
        self.bind_rule()
        self.drop = LoopingCall(self.transport.loseConnection)
        self.drop.start(DROPTIME, now=False)

    def bind_rule(self):
        for r in self.rules.rules:
            if self._host.port == r.fromport and self.type==r.fromtype and self.dir==r.fromdir:
                logging.info(str(self.transport)+': Server for connection (incoming): '+str(r))
                r.fromconnection=self
                self.bound=True
            if self._peer.port == r.fromport and self.type==r.fromtype and self.dir==r.fromdir:
                logging.info(str(self.transport)+': Recieving client for connection (incoming): '+str(r))
                r.fromconnection=self
                self.bound=True
            elif self._peer.host == r.ip and self._peer.port == r.port and self.type==r.type:
                logging.info(str(self.transport)+': Sending client for connection (outgoing): '+str(r))
                r.connection=self
                self.bound=True
            if self._host.port == r.port and self.type==r.type and self.dir==r.dir:
                logging.info(str(self.transport)+': Server for connection (outgoing): '+str(r))
                r.fromconnection=self
                self.bound=True
        if self.bound==False:
            logging.warning(str(self.transport)+' currently unmatched')
            self.transport.loseConnection()

    def connectionLost(self,reason):
        if len(self._LineReceiver__buffer)>0:
            self.lineReceived(self._LineReceiver__buffer)
        self.rules.del_connection(self)

    def lineReceived(self, line):
        line = line.strip('\r')
        logging.info(time.strftime('%H:%M:%S')+' Received: '+line)
        if self.dir == 'SEND':
            lines = self.rules.match(line,self.dir,self._peer.host, self._peer.port)
        else:
            lines = self.rules.match(line,self.dir,self._peer.host, self._host.port)

class VinculumFactory(ReconnectingClientFactory):
    def __init__(self,reactor):
        self.reactor=reactor
        self.maxDelay=30

    def buildProtocol(self,addr):
        return VinculumProtocol(reactor,self)

reactor.rules = Rules(reactor)
reactor.run()


