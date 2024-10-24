import sys, binascii, socket, hashlib, ssl

class ApiRos:
    "Routeros api"
    '''
    Класс взят с:
    https://help.mikrotik.com/docs/spaces/ROS/pages/47579209/Python3+Example
    '''
    def __init__(self, sk, debug=False):
        self.sk = sk
        self.currenttag = 0
        self.debug = debug
    def login(self, username, pwd):
        for repl, attrs in self.talk(["/login", "=name=" + username, "=password=" + pwd]):
            if repl == '!trap':
                return False
            elif '=ret' in attrs.keys():
                #for repl, attrs in self.talk(["/login"]):
                chal = binascii.unhexlify((attrs['=ret']).encode(sys.stdout.encoding))
                md = hashlib.md5()
                md.update(b'\x00')
                md.update(pwd.encode(sys.stdout.encoding))
                md.update(chal)
                for repl2, attrs2 in self.talk(["/login", "=name=" + username, "=response=00" + binascii.hexlify(md.digest()).decode(sys.stdout.encoding)]):
                    if repl2 == '!trap':
                        return False
        return True
    def talk(self, words):
        if self.writeSentence(words) == 0: return
        r = []
        while 1:
            i = self.readSentence();
            if len(i) == 0: continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[:j]] = w[j + 1:]
            r.append((reply, attrs))
            if reply == '!done': return r
    def writeSentence(self, words):
        ret = 0
        for w in words:
            self.writeWord(w)
            ret += 1
        self.writeWord('')
        return ret
    def readSentence(self):
        r = []
        while 1:
            w = self.readWord()
            if w == '': return r
            r.append(w)
    def writeWord(self, w):
        if self.debug: print("<<< " + w)
        self.writeLen(len(w))
        self.writeStr(w)
    def readWord(self):
        ret = self.readStr(self.readLen())
        if self.debug: print(">>> " + ret)
        return ret
    def writeLen(self, l):
        if l < 0x80:
            self.writeByte((l).to_bytes(1, sys.byteorder))
        elif l < 0x4000:
            l |= 0x8000
            tmp = (l >> 8) & 0xFF
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        elif l < 0x200000:
            l |= 0xC00000
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        elif l < 0x10000000:
            l |= 0xE0000000
            self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
        else:
            self.writeByte((0xF0).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
            self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
    def readLen(self):
        c = ord(self.readStr(1))
        # print (">rl> %i" % c)
        if (c & 0x80) == 0x00:
            pass
        elif (c & 0xC0) == 0x80:
            c &= ~0xC0
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xE0) == 0xC0:
            c &= ~0xE0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF0) == 0xE0:
            c &= ~0xF0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF8) == 0xF0:
            c = ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        return c
    def writeStr(self, str):
        n = 0
        while n < len(str):
            r = self.sk.send(bytes(str[n:], 'UTF-8'))
            if r == 0: raise RuntimeError("connection closed by remote end")
            n += r
    def writeByte(self, str):
        n = 0
        while n < len(str):
            r = self.sk.send(str[n:])
            if r == 0: raise RuntimeError("connection closed by remote end")
            n += r
    def readStr(self, length):
        ret = ''
        # print ("length: %i" % length)
        while len(ret) < length:
            s = self.sk.recv(length - len(ret))
            if s == b'': raise RuntimeError("connection closed by remote end")
            # print (b">>>" + s)
            # atgriezt kaa byte ja nav ascii chars
            if s >= (128).to_bytes(1, "big"):
                return s
            # print((">>> " + s.decode(sys.stdout.encoding, 'ignore')))
            ret += s.decode(sys.stdout.encoding, "replace")
        return ret
    
def connect(ApiRos,hst:str=None,use:str='admin',pas:str='',prt:int=None,tls:bool=False,debug:bool=False):
    if prt is None: prt = 8729 if tls else 8728
    s = socket.socket()  # Создаём сокет по умолчанию: socket.socket(2,1,0).
    if tls:  # Если нужно оборачиваем его в TLS.
        SSLContext = ssl.create_default_context()
        SSLContext.check_hostname = False
        SSLContext.verify_mode = ssl.CERT_NONE
        s = SSLContext.wrap_socket(s)
    try:
        s.connect((hst, prt))
    except ssl.SSLError:
        exit_code = 3
        print(f'По всей видимости, у сервиса api-ssl нет сертификата.\n\texit_code: {exit_code}')
        sys.exit(exit_code)
    except ConnectionRefusedError:
        exit_code = 2
        сервис = 'api-ssl' if tls else 'api'
        print(
            f'Проверте доступность устройства {hst}\nи включен ли на нём сервис {сервис} (port: {prt})\n\texit_code: {exit_code}')
        sys.exit(exit_code)
    api = ApiRos(s, debug=debug)
    if not api.login(use, pas):
        exit_code = 4
        print(f'Логин не пароль!\n\texit_code: {exit_code}')
        sys.exit(exit_code)
    return api

if __name__ == '__main__':
    hst='192.168.88.1'
    use='admin'
    pas=''
    prt, tls = None, True
    api = connect(ApiRos,hst=hst,use=use,pas=pas,prt=prt,tls=tls,debug=False)

    ret = api.talk(['/system/identity/print'])
    print(ret)
    print()

    ret = api.talk(['/interface/print','?type=ether'])
    for el in ret:
        print(el)


