from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import ReconnectingClientFactory
from os.path import exists, getmtime
from twisted.internet.task import LoopingCall

from twisted.internet import reactor
import re
import time

RULESFILE='vinculum.rules'
DROPTIME = 999999

class Rule:
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
        self.port=''
        self.fromtype=''
        self.fromip=None
        self.direction=''
        self.fromhost=''
        self.fromport=''
        self.parse_dest()
        self.parse_from()

    def __str__(self):
        ret = 'ma:'+str(self.match)
        ret = ret + ' mc:'+str(self.mcompile)
        ret = ret + ' fr:'+str(self.froms)
        ret = ret + ' dt:'+str(self.dest)
        ret = ret + ' sf:'+str(self.subfrom)
        ret = ret + ' st:'+str(self.subto)
        ret = ret + ' co:'+str(self.cont)
        ret = ret + ' ty:'+str(self.type)
        ret = ret + ' ho:'+str(self.host)
        ret = ret + ' ip:'+str(self.ip)
        ret = ret + ' po:'+str(self.port)
        ret = ret + ' ty:'+str(self.fromtype)
        ret = ret + ' di:'+str(self.direction)
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

    def parse_dest(self):
        try:
            parts = self.dest.split(':')
            if len(parts) <3:
                self.type= 'TCP'
                self.host = parts[0]
                self.port = int(parts[1])
            else:
                self.type = parts[0].upper()
                self.host = parts[1]
                self.port = int(parts[2])
            if self.host =='': self.ip=None
            else: self.reactor.resolve(self.host).addCallback(self.got_dest_ip)
        except:
            self.type = None
            self.host = None
            self.port = None

    def parse_from(self):
        try:
            parts = self.froms.split(':')
            if len(parts) <3:
                self.fromtype= 'TCP'
                self.direction= 'SEND'
                self.fromhost = parts[0]
                self.fromport = int(parts[1])
            else:
                try:
                    self.fromtype,self.direction = parts[0].split('-')
                    self.fromtype=self.fromtype.upper()
                    self.direction=self.direction.upper()
                    if self.direction != 'LISTEN': self.direction = 'SEND'
                except:
                    self.fromtype = parts[0].upper()
                    self.direction= 'SEND'
                self.fromhost = parts[1]
                self.fromport = int(parts[2])
            if self.fromhost in ['*','']: self.fromip=None
            else: self.reactor.resolve(self.fromhost).addCallback(self.got_from_ip)
        except:
            self.fromtype = None
            self.direction= None
            self.fromhost = None
            self.fromport = None

class Rules:
    def __init__(self,reactor):
        self.reactor=reactor
        self.rules=[]
        self.directory=[]
        self.rules_file=RULESFILE
        self.rules_last_read=0.0
        self.read_task = LoopingCall(self.read_rules)
        self.read_task.start(10, now=True)

    def parse_definition(self, text):
        parts = text.split(',')
        parts = [x.strip() for x in parts]
        if parts[5] in ['True','true','T','1']: cont = True
        else: cont=False
        return Rule(self.reactor,parts[0],parts[1],parts[2],parts[3],parts[4],cont)

    def read_rules(self):
        if not exists(self.rules_file):
            self.rules=[]
            print ('No rules file present!')
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
            print ('Adding rule '+str(rule))
            new_rules.append(rule)
        self.rules_last_read = mtime

        added = new_rules[:]
        lost = []
        sustained=[]
        for rule in self.rules:
            matched=False
            for nrule in new_rules:
                if rule.match==nrule.match and rule.froms==nrule.froms and rule.dest==nrule.dest and rule.subfrom==nrule.subfrom and rule.subto==nrule.subto and rule.cont==nrule.cont:
                    sustained.append(rule)
                    added.remove(nrule)
                    matched=True
            if not matched:
                lost.append(rule)
        self.rules = sustained + added
        self.dropConnections(lost)
        self.raiseConnections(added)

    def dropConnections(self,lost):
        for r in lost:
            try:
                r.connection.transport.loseConnection()
                r.connection.factory.stopTrying()
                r.fromconnection.transport.loseConnection()
                r.fromconnection.factory.stopTrying()
            except:
                pass

    def raiseConnections(self,new_rules):
        listens = set((x.fromtype,x.direction,x.fromhost,x.fromport) for x in new_rules) # deduplicate!
        for type,dir,host,port in listens:
            if host is None: continue
            if dir != 'LISTEN': continue
            inDir=False
            for entry in self.directory:
                if entry.direction == 'LISTEN' and entry.type == type and entry._host.port == port:
                    entry.bind_rule()
                    inDir=True
            if not inDir:
                print ('Listening on port: '+str(type)+':'+str(port))
                if type == 'TCP':
                    self.reactor.listenTCP(port, VinculumFactory(self.reactor))
                elif type == 'UDP':
                    self.reactor.listenUDP(port, VinculumFactory(self.reactor))
                elif type == 'SSL':
                    self.reactor.listenSSL(port, VinculumFactory(self.reactor))
                elif type == 'UNIX': #Using fromhost as unix socket address
                    self.reactor.listenUNIX(host, VinculumFactory(self.reactor))
        dests = set((x.type,x.host,x.port) for x in new_rules) # deduplicate!
        for x in new_rules: # make listen connections
            if x.direction != 'LISTEN':
                dests.add((x.fromtype,x.fromhost,x.fromport))
        for type,host,port in dests:
            if host is None: continue
            inDir=False
            for entry in self.directory:
                if entry._host.host == host and entry.type == type and entry._host.port == port:
                    entry.bind_rule()
                    inDir=True
            if not inDir:
                print ('Connecting to: '+str(type)+':'+str(host)+':'+str(port))
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

    def match(self,strn,ip):
        for rule in self.rules:
            m = rule.mcompile.match(strn)
            if m is not None:
                if rule.fromip == ip or rule.fromip is None:
                    print ('matched: '+str(rule.match)+' from '+str(ip))
                    line = strn
                    if rule.subfrom != '':
                        line = re.sub(rule.subfrom,rule.subto,strn)
                    if rule.connection:
                        try:
                            print ('sending: "'+line+'" to '+rule.dest)
                            rule.connection.sendLine(line)
                        except Exception as e:
                            print ('Sending line "'+str(line)+'" to '+rule.dest+' failed.')
                            print (e)
                    if not rule.cont: break

class VinculumProtocol(LineReceiver):
    delimiter='\n'
    def __init__(self,reactor,factory):
        self.reactor=reactor
        self.factory=factory
        self.rules = reactor.rules
        self._peer = None
        self._host = None

    def connectionMade(self):
        self._peer = self.transport.getPeer()
        self._host = self.transport.getHost()
        self.type,dir=[x.upper() for x in str(type(self.transport))[8:-2].split('.')][2:]
        if dir == 'SERVER':self.direction='LISTEN'
        else: self.direction='SEND'
        self.rules.add_connection(self)
        self.bind_rule()
        self.drop = LoopingCall(self.transport.loseConnection)
        self.drop.start(DROPTIME, now=False)

    def bind_rule(self):
        bound = False
        for r in self.rules.rules:
            if self._host.port == r.fromport and self.type==r.fromtype and self.direction==r.direction:
                print ('I am a server for this connection! '+str(r))
                r.fromconnection=self
                bound=True
            if self._peer.port == r.fromport and self.type==r.fromtype and self.direction==r.direction:
                print ('I am a recieving client for this connection! '+str(r))
                r.fromconnection=self
                bound=True
            elif self._peer.host == r.ip and self._peer.port == r.port and self.type==r.type:
                print ('I am a client for this connection! '+str(r))
                r.connection=self
                bound=True
        if bound==False:
            print ('I am unmatched!')
            self.transport.loseConnection()

    def connectionLost(self,reason):
        self.rules.del_connection(self)

    def lineReceived(self, line):
        line = line.rstrip('\r')
        line = line.lstrip('\r')
        print (time.strftime('%H:%M:%S')+' Received: '+line)
        lines = self.rules.match(line,self._peer.host)

class VinculumFactory(ReconnectingClientFactory):
    def __init__(self,reactor):
        self.reactor=reactor

    def buildProtocol(self,addr):
        return VinculumProtocol(reactor,self)

reactor.rules = Rules(reactor)
reactor.run()

