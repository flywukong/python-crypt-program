
import os
import sys
import random
import string
import imp
import base64
import marshal
import shutil
from binascii import b2a_hex,a2b_hex
# -*- coding: utf-8 -*- 
from Crypto.Cipher import AES 


SIGNATURE = 'AESENC:'
from Crypto import Random

#encrypt algorithm class

class AESCypher(object):

    def __init__(self,key,iv):
        self.key = key 
        self.mode = AES.MODE_CBC
        self.iv = iv

    def encrypt(self,text):

        cryptor = AES.new(self.key,self.mode,self.iv)
        #the length of the key is 16,24,32bytes
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            text = text + ('\0'*add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0'*add)
        self.ciphertext = cryptor.encrypt(text)

        return b2a_hex(self.ciphertext)

    def decrypt(self,text):
        cryptor = AES.new(self.key,self.mode,self.iv)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')




#base class of Finder

class BaseLoader(object):
    def modinfo(self, name, path):
        try:
            modinfo = imp.find_module(name.rsplit('.', 1)[-1], path)

        except ImportError:
            if '.' not in name:
                raise
            clean_path, clean_name = name.rsplit('.', 1)
            clean_path = [clean_path.replace('.', '/')]
            modinfo = imp.find_module(clean_name, clean_path)

        file, pathname, (suffix, mode, type_) = modinfo
        
        if type_ == imp.PY_SOURCE:
            filename = pathname
        elif type_ == imp.PY_COMPILED:
            filename = pathname[:-1]
        elif type_ == imp.PKG_DIRECTORY:
            filename = os.path.join(pathname, '__init__.py')
        else:
            return (None, None)
        return (filename, modinfo)

#Class Loader

class Loader(BaseLoader):
    def __init__(self, name, path):
        self.name = name
        self.path = path


    def load_module(self, name):
#        if name in sys.modules:
#            return sys.modules[name]
        
        filename, modinfo = self.modinfo(self.name, self.path)
        if filename is None and modinfo is None:
            return None
        
        file = modinfo[0] or open(filename, 'r')

        
        input = open(filename[:-2]+"pyc",'rb')           #decrypt the PYC file 
                
        input.seek(len(SIGNATURE))      

        SECRET = a2b_hex(input.read(64))
        
        input.seek(-32,2)
        iv = a2b_hex(input.read(32))

        input.seek(len(SIGNATURE)+64,0) 
        
        content = input.read()
        content = content[:-32]
        cipher = AESCypher(SECRET,iv)

        PycFile = cipher.decrypt(content)

        code_obj = marshal.loads(PycFile[8:])


        module = imp.new_module(name)
        module.__file__ = filename
        module.__path__ = [os.path.dirname(os.path.abspath(file.name))]
        module.__loader__ = self
        sys.modules[name] = module
        
        exec(code_obj,module.__dict__)

        print "encrypted module loaded: {0}{1}".format(name,self.path)
        return module

class Loader(BaseLoader):
    def __init__(self, name, path):
        self.name = name
        self.path = path


    def load_module(self, name):
#        if name in sys.modules:
#            return sys.modules[name]
     
        filename, modinfo = self.modinfo(self.name, self.path)
        if filename is None and modinfo is None:
            return None
     
        file = modinfo[0] or open(filename, 'r')

     
        input = open(filename[:-2]+"pyc",'rb')           #decrypt the PYC file 
     
        input.seek(len(SIGNATURE))    

        SECRET = a2b_hex(input.read(64))
     
        input.seek(-32,2)
        iv = a2b_hex(input.read(32))

        input.seek(len(SIGNATURE)+64,0) 
     
        content = input.read()
        content = content[:-32]
        cipher = AESCypher(SECRET,iv)

        PycFile = cipher.decrypt(content)

        code_obj = marshal.loads(PycFile[8:])


        module = imp.new_module(name)
        module.__file__ = filename
        module.__path__ = [os.path.dirname(os.path.abspath(file.name))]
        module.__loader__ = self
        sys.modules[name] = module

        exec(code_obj,module.__dict__)

        print "encrypted module loaded: {0}{1}".format(name,self.path)
        return module

#Class finder

class Finder(BaseLoader):
    def find_module(self, name, path=None):
        
        filename, modinfo = self.modinfo(name, path)
        if filename is None and modinfo is None:
             return None

        file2 = open('modinfo.txt','w')
        content = '{0}/{1}'.format(name,path)
        file2.write(content)

       # file = open(filename,'r')
        file = modinfo[0] or open(filename, 'r')
        if file.read(len(SIGNATURE)) == SIGNATURE :
            print "encrypted module found:{0} (at {1})".format(name,path)
            return Loader(name, path)

#register hook

def install_hook():
    sys.meta_path.insert(0, Finder())


#encrypt app function
def encrypt_all(location):
  


    for root, dirs, files in os.walk(location):
        files = (f for f in files if f.endswith('.pyc'))
        for name in files:
            enc_name = '{0}/{1}pye'.format(root, name[:-3])
            orig_name = '{0}/{1}'.format(root, name)
            
            with open(orig_name,'r') as input:
                with open(enc_name,'wb') as output:
                    iv = ''.join(random.sample(string.ascii_letters , 16))
                    SECRET = ''.join(random.sample(string.ascii_letters, 32))

                    cipher = AESCypher(SECRET,iv)
                    content = cipher.encrypt(input.read())
                    SECRET = b2a_hex(SECRET)
                    iv = b2a_hex(iv)
                    content = '{0}{1}{2}{3}'.format(SIGNATURE,SECRET,content,iv)
                    output.write(content)

            os.remove(orig_name)
            os.rename(enc_name,orig_name)

          #  os.rename(enc_name,orig_name)


if __name__ == '__main__':
    encrypt_all(sys.argv[1])
