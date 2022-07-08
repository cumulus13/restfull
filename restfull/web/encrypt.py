from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from pydebugger.debug import debug
import sys
import os
import importlib

#settings = importlib.import_module(os.path.join(os.path.dirname((os.path.dirname(__file__))), 'vis_p', 'settings'))

class Crypt:
    salt_key='SlTKeYOpHygTYkP3'
    salt = salt_key.encode('utf8')
    enc_dec_method = 'utf-8'

    def __init__(self, salt='SlTKeYOpHygTYkP3'):
        if salt:
            self.salt = salt.encode('utf8')
        # self.enc_dec_method = 'utf-8'

    @classmethod
    def encrypt(self, str_to_enc, str_key):
        debug(str_to_enc = str_to_enc)
        try:
            aes_obj = AES.new(str_key.encode('utf-8'), AES.MODE_CFB, self.salt)
            hx_enc = aes_obj.encrypt(str_to_enc.encode('utf8'))
            mret = b64encode(hx_enc).decode(self.enc_dec_method)
            debug(mret = mret)
            return mret
        except ValueError as value_error:
            if value_error.args[0] == 'IV must be 16 bytes long':
                raise ValueError('Encryption Error: SALT must be 16 characters long')
            elif value_error.args[0] == 'AES key must be either 16, 24, or 32 bytes long':
                raise ValueError('Encryption Error: Encryption key must be either 16, 24, or 32 characters long')
            else:
                raise ValueError(value_error)

    @classmethod
    def decrypt(self, enc_str, str_key):
        debug(enc_str = enc_str)
        if isinstance(enc_str, bytes):
            enc_str = enc_str.decode('utf-8')
        try:
            aes_obj = AES.new(str_key.encode('utf8'), AES.MODE_CFB, self.salt)
            str_tmp = b64decode(enc_str.encode(self.enc_dec_method))
            str_dec = aes_obj.decrypt(str_tmp)
            mret = str_dec.decode(self.enc_dec_method)
            debug(mret = mret)
            return mret
        except ValueError as value_error:
            if value_error.args[0] == 'IV must be 16 bytes long':
                raise ValueError('Decryption Error: SALT must be 16 characters long')
            elif value_error.args[0] == 'AES key must be either 16, 24, or 32 bytes long':
                raise ValueError('Decryption Error: Encryption key must be either 16, 24, or 32 characters long')
            else:
                raise ValueError(value_error)
            
def usage():
    import argparse
    parser = argparse.ArgumentParser(formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument('TEXT', help = 'Text to encrypt or decrypt', action = 'store')
    parser.add_argument('-e', '--encrypt', help = 'Encrypt action', action = 'store_true')
    parser.add_argument('-d', '--decrypt', help = 'Decrypt action', action = 'store_true')
    if len(sys.argv) == 1:
        parser.print_help()
    else:
        args = parser.parse_args()
        ENCRYPT_KEY = '8KkTRZkfVm3osKXVFkB0EhVEok2sGcZI'
        #test_key = '9KkTRZkfVm3osKXVFkB0EhVEok2sGcXX'
        TEXT_ENC = Crypt.encrypt(args.TEXT, ENCRYPT_KEY)
        TEXT_DEC = Crypt.decrypt(TEXT_ENC, ENCRYPT_KEY)
        print("\n")
        print(f'Encrypted:{TEXT_ENC}  | Decrypted:{TEXT_DEC}')
        
        

if __name__ == '__main__':
    
    usage()

    # test_crpt = Crypt()
    #test_text1 = """Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
    #tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
    #quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
    #consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
    #cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
    #proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    #Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
    #tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
    #quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
    #consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
    #cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
    #proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    #Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
    #tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
    #quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
    #consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
    #cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
    #proident, sunt in culpa qui officia deserunt mollit anim id est laborum."""

    #test_text = "12345678"

    # test_key = '8KkTRZkfVm3osKXVFkB0EhVEok2sGcZI'
    
    #test_key = '9KkTRZkfVm3osKXVFkB0EhVEok2sGcXX'
    #TEXT_ENC = Crypt.encrypt(test_text, test_key)
    #test_dec_text = Crypt.decrypt(test_enc_text, test_key)
    #print(f'Encrypted:{test_enc_text}  | Decrypted:{test_dec_text}')