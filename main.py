from twisted.protocols.basic import LineReceiver
from twisted.internet.protocol import ReconnectingClientFactory
from os.path import exists, getmtime
from twisted.internet.task import LoopingCall

from twisted.internet import reactor
import re
import time

RULESFILE='vinculum.rules'
PORT = 8123
MY_IPS=['127.0.0.1','192.168.2.251']

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
        try:
            parts = text.split(',')
            parts = [x.strip() for x in parts]
            mcompile = re.compile(parts[0])
            if parts[4] in ['True','true','T','1']: cont = True
            else: cont=False
            return {'match':parts[0],'mcompile':mcompile,'dest':parts[1],'cont':cont,'subfrom':parts[2],'subto':parts[3],'conn':None}
        except Exception as e:
            print (e)
            pass

    def read_rules(self):
        if not exists(self.rules_file):
            self.rules=[]
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
        self.rules = new_rules
        self.rules_last_read = mtime
        self.rules_connect()

    def rules_connect(self):
        for c in self.directory:
            c.bind_rule()
        dests = set(x['dest'] for x in self.rules) # deduplicate!
        for conn in dests:
            host, port = conn.split(':')
            port = int(port)
            inDir=False
            for entry in self.directory:
                if entry._peer.host == host and entry._peer.port == port:
                    inDir=True
                if entry._host.host == host and entry._host.port == port:
                    inDir=True
            if not inDir:
                print ('Connecting to: '+str(host)+', '+str(port))
                self.reactor.connectTCP(host,port,VinculumFactory()) #Auto-adds itself.

    def add_connection(self,connection):
        if connection not in self.directory:
            self.directory.append(connection)

    def del_connection(self,connection):
        if connection in self.directory:
            self.directory.remove(connection)

    def match(self,strn):
        ret = []
        for rule in self.rules:
            print ('Searching rule: '+str(rule))
            m = re.match(rule['match'], strn)
            if m is not None:
                print ('matched: '+str(rule['match']))
                line = strn
                if rule['subfrom'] != '' and rule['subto'] != '':
                    print ('matching: '+str(rule['subfrom']))
                    line = re.sub(rule['subfrom'],rule['subto'],strn)
                try:
                    rule['conn'].sendLine(line)
                except Exception as e:
                    print ('Sending line "'+str(line)+'" to '+str(rule['dest'])+' failed.')
                    print (e)
                if not rule['cont']: break
        return ret

class VinculumProtocol(LineReceiver):
    delimiter='\n'
    def __init__(self):
        self.rules = reactor.rules
        self._peer = None
        self._host = None

    def connectionMade(self):
        self._peer = self.transport.getPeer()
        self._host = self.transport.getHost()
        self.rules.add_connection(self)
        self.bind_rule()

    def bind_rule(self):
        for entry in self.rules.rules:
            host, port = entry['dest'].split(':')
            port = int(port)
            if self._peer.host == host and self._peer.port == port:
                print ('I am a server for this connection! '+str(entry))
                entry['conn']=self
            if self._host.host == host and self._host.port == port:
                print ('I am a client for this connection! '+str(entry))
                entry['conn']=self

    def connectionLost(self,reason):
        self.rules.del_connection(self)

    def lineReceived(self, line):
        line = line.rstrip('\r')
        print ('Received: '+line)
        lines = self.rules.match(line)
        print (str(lines))
        for line in lines:
            print ('Translated to: '+str(line))

class VinculumFactory(ReconnectingClientFactory):
    def buildProtocol(self,addr):
        return VinculumProtocol()

reactor.rules = Rules(reactor)
reactor.listenTCP(PORT, VinculumFactory())
reactor.run()

