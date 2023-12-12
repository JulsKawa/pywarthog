from random import randint
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import RIPEMD160, SHA256
import requests
import json
import struct

# class, need to be initilized with node url 
class Warthog:
    def __init__(self, url):
        self.url = url
        super().__init__()
        
    def get_balance(self,address):
        baseurl = self.url
        result = requests.get(baseurl + f'/account/{address}/balance').content
        balance = json.loads(result)
        return balance["data"]["balance"]
              
class Key(Warthog):
    def __init__(self, url):
        super().__init__(url)
        
    def gen_pk():
        return SigningKey.generate(curve=SECP256k1)
    
    def pk_to_hex(pk):
        return pk.to_string().hex()
    
    def hex_to_pk(pkhex):
        return SigningKey.from_string(bytes.fromhex(pkhex),curve=SECP256k1)
    
    def derive_pubkey(pk):
        return pk.get_verifying_key().to_string('compressed')
    
    def pubkey_to_hex(pubkey):
        return pubkey.hex()
    
    def pubkey_to_addr(pubkey):
        sha = SHA256.SHA256Hash(pubkey).digest()
        addr_raw = RIPEMD160.RIPEMD160Hash(sha).digest()
        addr_hash = SHA256.SHA256Hash(addr_raw).digest()
        checksum = addr_hash[0:4]
        return addr_raw + checksum
    
    def addr_to_hex(addr):
        return addr.hex()
    
class Transaction(Warthog):
    def get_pinhash():   
        baseurl = "http://localhost:3000"
        head_raw = requests.get(baseurl+'/chain/head').content
        head = json.loads(head_raw)
        return head["data"]["pinHash"]
    
    def get_pinheight():   
        baseurl = "http://localhost:3000"
        head_raw = requests.get(baseurl+'/chain/head').content
        head = json.loads(head_raw)
        return head["data"]["pinHeight"]
        
    def get_nonceid():
        return randint(0, 4294967295)  
    
    def send_wart(url, recipient : str , amount : int, pk : SigningKey):
        baseurl = url
        
        # send parameters
        nonceId = Transaction.get_nonceid() # 32 bit number, unique per pinHash and pinHeight
        toAddr = recipient # burn destination address
        amountE8 = amount * 10E8
        
        # round fee from WART amount
        rawFeeE8 = "0.00000001" # this needs to be rounded
        result = requests.get(baseurl+'/tools/encode16bit/from_string/'+rawFeeE8).content
        encode16bit_result = json.loads(result)
        feeE8 = encode16bit_result["data"]["roundedE8"] # 9992
        
        pinHash = Transaction.get_pinhash()
        pinHeight = Transaction.get_pinheight()
        
        to_sign =\
        bytes.fromhex(pinHash)+\
        pinHeight.to_bytes(4, byteorder='big') +\
        nonceId.to_bytes(4, byteorder='big') +\
        b'\x00\x00\x00'+\
        feeE8.to_bytes(8, byteorder='big')+\
        bytes.fromhex(toAddr)[0:20]+\
        int(amountE8).to_bytes(8, byteorder='big')
        
        # create signature
        from pycoin.ecdsa.secp256k1 import secp256k1_generator
        from hashlib import sha256
        private_key = pk.privkey.secret_multiplier 
        digest = sha256(to_sign).digest()
        
        # sign with recovery id
        (r, s, rec_id) = secp256k1_generator.sign_with_recid(private_key, int.from_bytes(digest, 'big'))
        
        # normalize to lower s
        if s > secp256k1_generator.order()/2: #
            s = secp256k1_generator.order() - s
            rec_id ^= 1 # https://github.com/bitcoin-core/secp256k1/blob/e72103932d5421f3ae501f4eba5452b1b454cb6e/src/ecdsa_impl.h#L295
        signature65 = r.to_bytes(32,byteorder='big')+s.to_bytes(32,byteorder='big')+rec_id.to_bytes(1,byteorder='big')
        
        # post transaction request to warthog node
        postdata = {
        "pinHeight": pinHeight,
        "nonceId": nonceId,
        "toAddr": toAddr,
        "amountE8": amountE8,
        "feeE8": feeE8,
        "signature65": signature65.hex()
        }
        rep = requests.post(baseurl + "/transaction/add", json = postdata)
        print(postdata)
        rep.content
        return rep.content
            
    