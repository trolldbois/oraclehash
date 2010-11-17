#!/usr/bin/python

from Crypto.Cipher import DES
## new(key, [mode], [IV]): Return a new DES encryption object.
import sys
import os

class Generator:
  '''
  A 1993 post on the comp.databases.oracle newsgroup describes the algorithm in detail,
identifying an unknown fixed key as an input parameter. This key value was later
published in the book "Special Ops", providing sufficient information to reproduce the
algorithm. The algorithm can be described as follows:

1. Concatenate the username and the password to produce a plaintext string;
2. Convert the plaintext string to uppercase characters;
3. Convert the plaintext string to multi-byte storage format; ASCII characters have the
high byte set to 0x00;
4. Encrypt the plaintext string (padded with 0s if necessary to the next even block length)
using the DES algorithm in cipher block chaining (CBC) mode with a fixed key value of
0x0123456789ABCDEF;
5. Encrypt the plaintext string again with DES-CBC, but using the last block of the output
of the previous step (ignoring parity bits) as the encryption key. The last block of the
output is converted into a printable string to produce the password hash value.
  '''

  __tests=[
	("SYSTEM","9EEDFA0AD26C6D52", "THALES" ),
	("SIMON","4F8BC1809CB2AF77", "A"),
	("SIMON","183D72325548EF11", "THALES2" ),
	("SIMON","C4EB3152E17F24A4", "TST" ),
	("BOB","b02c8e79ed2e7f46", "LAPIN" ),
	("BOB","6bb4e95898c88011", "LAPINE" ),
	("BOB","cdc6b483874b875b", "GLOUGLOU" ),
	("BOB","ef1f9139db2d5279", "GLOUGLOUTER" ),
	("BOB","c0ee5107c9a080c1", "AZERTYUIOP" ),
	("BOB","99e8b231d33772f9", "CANARDWC" ),
	("BOB","da3224126a67c8ed", "COUCOU_COUCOU" ),
	("BOB","ec8147abb3373d53", "LONG_MOT_DE_PASSE_OUI" ),

  ("IGC","C767F3BD90C5C0C2", "OAMMV100"),
  ("CMS","F0EF99D77624EFFC","OAMMV100")]
  #
  def __init__(self):
    '''
static void oracle_init(void)
{
	unsigned char deskey[8];

	deskey[0] = 0x01;
	deskey[1] = 0x23;
	deskey[2] = 0x45;
	deskey[3] = 0x67;
	deskey[4] = 0x89;
	deskey[5] = 0xab;
	deskey[6] = 0xcd;
	deskey[7] = 0xef;

	DES_set_key((DES_cblock *)deskey, &desschedule1);
}
  '''
    self.deskey="\x01\x23\x45\x67\x89\xab\xcd\xef"
    return
  #
  def set_salt(self,salt):
    '''
static void oracle_set_salt(void *salt) {
	salt_length = *(unsigned short *)salt;
	memcpy(cur_salt, (char *)salt+2, salt_length);
}
  @john
   '''
    self.salt=salt
    return
  #
  def set_data(self,secret,salt=None):
    if (salt is None):
      salt=self.salt
    # 1 et 2
    data=(salt+secret).upper()
    #print "** CAT  : ", data
    self.data=''
    # 3. high bytes
    for ch in data:
      self.data+='\x00%c'%ch
    #print "** HIGH : ", self.data
    # 4a. pad
    n=len(self.data) % 8 
    if ( n > 0):
       self.data+=(8-n)*'\00'
    #print "** PAD  : ", self.data
    return
  #
  def crypt(self):
    '''
    memcpy((char *)cur_salt + salt_length, cur_key, key_length);
    DES_ncbc_encrypt((unsigned char *)cur_salt, buf, l, &desschedule1, (DES_cblock *) crypt_key, DES_ENCRYPT);
    '''
    #print "data : ",self.data
    self.des=DES.new(self.deskey[:8],mode=DES.MODE_CBC)
    cryptedblocks=self.des.encrypt(self.data)
    #5. Encrypt the plaintext string again with DES-CBC, but using the last block of the output
    #of the previous step (ignoring parity bits) as the encryption key. The last block of the
    #output is converted into a printable string to produce the password hash value.
    block=cryptedblocks[-8:]
    #print "BLOCK :",block
    # ignoring parity bit...
    des2=DES.new(block,mode=DES.MODE_CBC)
    cryptedfinal=des2.encrypt(self.data)
    crypted=cryptedfinal[-8:]
    return crypted  
  #
  def hash(self,secret,username=None):
    self.salt=None
    self.secret=None
    self.data=None 
    if (username is None ):
      if (self.salt is None):
        print 'please salt before eating...'
        return
      else:
        # salting is done
        print "salting is done"
        pass
    else:
      self.set_salt(username)
    #print "salt : ",self.salt
    # ok, lets hash
    self.set_data(secret)
    hash=self.crypt()
    toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
    ret=toHex(hash).upper()
    #print '%s:%s'%(username,ret)
    return username.upper(),ret
  
  def _test(self):
    for user,hash,password in self.__tests:
      _u,_h=self.hash(password,user)
      if ( _h == hash.upper() ):
        print user,hash,password , ' == ', _u, _h
      else :
        print user,hash,password , ' != ', _u, _h


def _test():
  user="CMS"
  secret="OAMMV100"
  cmscrypted="F0EF99D77624EFFC"
  cmscrypted="\xF0\xEF\x99\xD7\x76\x24\xEF\xFC"
  toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
  import Crypto
  from Crypto.Cipher import DES
  import base64
  import os
  deskey="\x01\x23\x45\x67\x89\xab\xcd\xef"
  des=DES.new(deskey[:8],mode=DES.MODE_CBC)
  salt="CMS".upper()
  secret="OAMMV100".upper()
  #1. Concatenate the username and the password to produce a plaintext string;
  #2. Convert the plaintext string to uppercase characters;
  tmpdata=(salt+secret).upper()
  #3. Convert the plaintext string to multi-byte storage format; ASCII characters have the
  #high byte set to 0x00;
  data=''
  for ch in tmpdata:
    data+='\x00%c'%ch
  #4. Encrypt the plaintext string (padded with 0s if necessary to the next even block length)
  #using the DES algorithm in cipher block chaining (CBC) mode with a fixed key value of
  #0x0123456789ABCDEF;
  n=len(data) % 8 
  if ( n > 0):
    data+=(8-n)*'\00'
  print "salt : ", salt
  print "data : ",data
  #
  cryptedblocks=des.encrypt(data)
  #5. Encrypt the plaintext string again with DES-CBC, but using the last block of the output
  #of the previous step (ignoring parity bits) as the encryption key. The last block of the
  #output is converted into a printable string to produce the password hash value.
  block=cryptedblocks[-8:]
  print "BLOCK :",block
  # ignoring parity bit...
  des2=DES.new(block,mode=DES.MODE_CBC)
  cryptedfinal=des2.encrypt(data)
  crypted=cryptedfinal[-8:]
  print "CMS:%s"%(toHex(crypted))
  return


def main(argv):
  if (len(argv) == 1):
    line=argv[0]
    userpass=line.split(':')
    if (len(userpass) != 2):
      print "mauvais format : attendu <USER:HASH-16-CHAR-ORACLE>"
      return
    user=userpass[0]
    password=userpass[1]
  elif (len(argv) == 2):
    user=argv[0]
    password=argv[1]
  else:
    print "usage: oraclehash <USER:HASH-16-CHAR-ORACLE> | <user> <password>"
    return
  # ok let's go
  g=Generator()
  u,hash=g.hash(password,user)
  print '%s:%s'%(u,hash)
  return

if __name__ == '__main__':
  main(sys.argv[1:])


