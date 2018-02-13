import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os.path
import ast
from base64 import b64encode, b64decode

def generate_keys():
	if os.path.exists("/root/private_key.txt"):
		os.remove("/root/private_key.txt")

	if os.path.exists('public_key.txt'):
		os.remove('public_key.txt')

	if os.path.exists('secret_key.txt'):
		os.remove('secret_key.txt')
	
	secret_key = Random.new().read(16).encode('hex')
	private_key = RSA.generate(2048)
	public_key = private_key.publickey()

	S = open('private_key.txt', 'wr')
	S.write(private_key.exportKey())
	S.close()

	P = open('public_key.txt','wr')
	P.write(public_key.exportKey())
	P.close()

	K = open('secret_key.txt','wr')
	K.write(secret_key)
	K.close()
	
	print 'secret key: \n'+secret_key
	print 'public key: \n'+str(public_key.exportKey())
	print 'private key: \n'+str(private_key.exportKey())


def message():
	tekst = raw_input("message:")
	
	Ntekst = open('text.txt', 'wr')
	Ntekst.write(str(tekst))
	Ntekst.close()

def crypt():
	if os.path.exists('crypt_text_rsa.txt'):
		os.remove('crypt_text_rsa.txt')

	if os.path.exists('crypt_text_aes.txt'):
		os.remove('crypt_text_aes.txt')
	
	public_key = RSA.importKey(open('public_key.txt', 'r').read())
	secret_key = open('secret_key.txt', 'r').read()	
	
	tekst = open('text.txt', 'r').read()
	enc_tekst = public_key.encrypt(tekst, 32)	

	Kript = open('crypt_text_rsa.txt', 'wr')
	Kript.write(str(enc_tekst))
	Kript.close()
	 
	iv = Random.new().read(AES.block_size) #block_size=16 bytes(size of data blocks)
	cipher = AES.new(secret_key, AES.MODE_CFB, iv) #new(key, *args, **kwards)
	aes_kript = cipher.encrypt(tekst)

	IV = open('iv.txt', 'wr')
	IV.write(str(iv))
	IV.close()

	AKript = open('crypt_text_aes.txt', 'wr')
	AKript.write(str(aes_kript))
	AKript.close()	
	print 'asimetric crypt-----'	
	print 'RSA crypt text: '+str(enc_tekst)
	print '\nsimetric kriptiranje-----'	
	print iv
	print 'AES crypt text: '+str(aes_kript)	

def decrypt():
	rsa_private_key = RSA.importKey(open('private_key.txt', 'r').read())	
	tekst1 = open('crypt_text_rsa.txt', 'r').read()
	aes_kript = open('crypt_text_aes.txt', 'r').read()
	secret_key = open('secret_key.txt', 'r').read()
	iv = open('iv.txt', 'r').read()

	dec_tekst = AES.new(secret_key, AES.MODE_CFB, iv)
	aes_dec_tekst = dec_tekst.decrypt(aes_kript) 

	print 'AES:'
	print aes_dec_tekst
	print 'RSA:'
	print rsa_private_key.decrypt(ast.literal_eval(str(tekst1))) 

def message_hash():
	if os.path.exists('message_hash'):
		os.remove('message_hash')
	
	tekst = open('text.txt', 'r').read()
	hash = SHA256.new(tekst).hexdigest()

	Sp = open('message_hash', 'wb')
	Sp.write(str(hash))
	Sp.close()
	print hash

def digital_signature():
	if os.path.exists('digital_signature'):
		os.remove('digital_signature')
	
	private_key = RSA.importKey(open('private_key.txt', 'r').read())		
	tekst = open('text.txt', 'r').read()
	hash = SHA256.new(tekst).hexdigest()

	signature = private_key.sign(hash, '')
	signature = b64encode(str(signature))
	Dp = open('digital_signature', 'wb')
	Dp.write(str(signature))
	Dp.close()
	print signature
	
def signature_check():	
	signature = open('digital_signature', 'rb').read()
	signature = b64decode(signature)
	public_key = RSA.importKey(open('public_key.txt', 'r').read())
	
	tekst = open('text.txt', 'r').read()
	hash = SHA256.new(tekst).hexdigest()
	
	if(public_key.verify(hash, ast.literal_eval(str(signature)))):
		print 'Digital signature IS VALID'
	else: 
		print 'Digital signature IS NOT VALID'
