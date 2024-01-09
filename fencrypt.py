#!/usr/bin/env python3

import os
import sys
import argparse
import getpass
from hashlib import pbkdf2_hmac
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii
import hmac
import hashlib
import json
import regex
import codecs
import random
from pathlib import Path
import unicodedata
from chardet import detect

parser = argparse.ArgumentParser(description='program that encrypt or decrypt individual files using a password, and allow to search for key wordsin ecnrypted files.')
parser.add_argument('-j', '--json', action='store_true')
group = parser.add_mutually_exclusive_group()
group.add_argument('-e', '--enc', action = 'store_true')
group.add_argument('-d', '--dec', action = 'store_true')
group.add_argument('-s', '--search', action = 'store_true')
parser.add_argument('args', nargs='*')
args = parser.parse_args()

def get_password():
    # if sys.stdin.isatty():
    password = getpass.getpass("password:  ").encode("utf-8")
    if len(password) > 0:
        return password
    sys.exit(1)
   # else:
    # return sys.stdin.readline().strip().encode("utf-8")


def get_encoding_type(file):
    with open(file, 'rb') as f:
        rawdata = f.read()
    return detect(rawdata)['encoding']


def createmasterkey(password, salt):
    pw = password
    salt = salt
    key = pbkdf2_hmac('sha256', pw, salt, iterations=250000)
    return key

# function to add i to nonce


def incrementing(a, i):
    return (int.from_bytes(a, 'big') + i).to_bytes(16, 'big')


def xor_bytes(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])


def one_ctr_block(key, nonce_plus_ctr):
    ctx = AES.new(key, mode=AES.MODE_CTR, counter=Counter.new(128))
    return ctx.encrypt(nonce_plus_ctr)


def createkeyseries(masterkey):
    base_key = masterkey[:16]
    nonce = masterkey[16:]
    return (one_ctr_block(base_key, nonce),
            one_ctr_block(base_key, incrementing(nonce, 1)),
            one_ctr_block(base_key, incrementing(nonce, 2)),
            one_ctr_block(base_key, incrementing(nonce, 3)),
            one_ctr_block(base_key, incrementing(nonce, 4)),
            one_ctr_block(base_key, incrementing(nonce, 5)),
            one_ctr_block(base_key, incrementing(nonce, 6))
            )


def ctr_round(key, data):
    if type(data) != bytes:
        data = data.encode('utf-8')
    lin = data[:16]
    rin = data[16:]

    # Split rin into 16 byte blocks
    datablock = []
    for i in range(0, len(rin), 16):
        if i + 16 <= len(rin):
            datablock.append(rin[i:i + 16])
    if len(rin) % 16 != 0:
        datablock.append(rin[len(rin) - (len(rin) % 16):])

    counter = 0
    rout = b''
    for i in datablock:
        rout += xor_bytes(one_ctr_block(key, incrementing(lin, counter)), i)
        counter += 1
    return lin + rout


def hmac_round(key, data):
    lin = data[:16]
    rin = data[16:]
    lout = xor_bytes(hmac.new(key, rin, hashlib.sha256).digest(), lin)
    return lout + rin


def enc(keys, pt):
    round1 = ctr_round(keys[0], pt)
    round2 = hmac_round(keys[1], round1)
    round3 = ctr_round(keys[2], round2)
    round4 = hmac_round(keys[3], round3)
    return round4


def dec(keys, ct):
    round1 = hmac_round(keys[3], ct)
    round2 = ctr_round(keys[2], round1)
    round3 = hmac_round(keys[1], round2)
    round4 = ctr_round(keys[0], round3)
    return round4


def createmetadatafile(filename, salt, validator, macdct, searchterms):
    # convert bytes objects to hex
    metadata = {"salt": salt, "validator": validator, "mac": macdct,
                "terms": searchterms}
    metadatajson = json.dumps(metadata)
    metadadatafilename = ".fenc-meta."+ filename
    with open(metadadatafilename, 'w') as metafile:
        metafile.write(metadatajson)
    metafile.close()


def getmetadatacontents(file):
    metadatafilename = ".fenc-meta."+file
    try:
        metadata = open(metadatafilename, 'r')
        metadatafilecontents = json.load(metadata)
        metadata.close()
        return (metadatafilecontents)
    except:
        sys.exit(1)


def deletemetadatafile(file):
    metadatafilename = '.fenc-meta.'+file
    if os.path.exists(metadatafilename):
        os.remove(metadatafilename)
    else:
        print("Meta file does not exist", file=sys.stderr)

def dec_file(file, password, outputjson):
    filemetadata = getmetadatacontents(file)
    salt = filemetadata['salt']
    salt = bytes.fromhex(salt)

    masterkey = createmasterkey(password, salt)
    outputjson[file] = masterkey.hex()
    # Generate the password validator and key schedule for each file, per above.
    validator, fk1, fk2, fk3, fk4, mackey, searchkey = createkeyseries(masterkey)
    feistelkeys = [fk1, fk2, fk3, fk4]
    if filemetadata["validator"] != validator.hex():
        print("wrong validator", file=sys.stderr)
        sys.exit(1)
    openfile = open(file, 'rb')
    encryptedtext = openfile.read()
    openfile.close()
    ciphertextmacd = hmac.new(mackey, encryptedtext, hashlib.sha256).hexdigest()
    if filemetadata["mac"] != ciphertextmacd:
        print("wrong mac", file=sys.stderr)
        sys.exit(1)
    plaintext = dec(feistelkeys, encryptedtext).decode('utf-8')
    return(plaintext, outputjson)

def enc_file(plaintextfile, password, outputjson):
    salt = secrets.token_bytes(16)
    masterkey = createmasterkey(password, salt)
    outputjson[plaintextfile] = masterkey.hex()
    # Generate the password validator and key schedule for each file, per above.
    validator, fk1, fk2, fk3, fk4, mackey, searchkey = createkeyseries(masterkey)
    feistelkeys = [fk1, fk2, fk3, fk4]
    searchterms = []
    with open(plaintextfile, 'rb') as encrypted:
        plaintext = encrypted.read()
        encrypted.close()


        terms = regex.findall(
        r"[\p{L}\p{Mn}\p{Nd}\p{Pc}]+", str(plaintext))
        terms2 = []
        for word in terms:
            if (len(word) > 3) and (len(word) < 13):
                terms2.append(unicodedata.normalize('NFC', word))

        casefoldinglist = []
        for word in terms2:
            for i in range(4, len(word)):
                casefoldinglist.append(word[0:i].casefold() + "*")
            casefoldinglist.append(word.casefold())

        macsearchtermslist = []
        for word in casefoldinglist:
            casefold = hmac.new(searchkey, word.encode(
                'utf-8'), hashlib.sha256).hexdigest()
            
            macsearchtermslist.append(casefold)
        
        macsearchtermslist = list(set(macsearchtermslist))
        macsearchtermslist.sort()
        searchterms.extend(macsearchtermslist)
        
    ciphertext = enc(feistelkeys, plaintext)
    mac = hmac.new(mackey, ciphertext, hashlib.sha256).hexdigest()
    with open(plaintextfile, 'wb') as encrypted:
        encrypted.write(ciphertext)
    createmetadatafile(plaintextfile, salt.hex(), validator.hex(), mac, searchterms)
    
    return(ciphertext, outputjson)


def search_file(searchterms, searchkey, file, jflag):
    encrypted_json = getmetadatacontents(file)
    if jflag:
        json.dump(encrypted_json, sys.stdout)
    encrypted_terms = encrypted_json['terms']

    terms2 = []
    for word in searchterms:
        if (len(word) > 3) and (len(word) < 13):
            terms2.append(unicodedata.normalize('NFC', word.casefold()))

    casefoldinglist = []
    for word in terms2:
        for i in range(4, len(word)):
            casefoldinglist.append(word[0:i].casefold() + "*")
        casefoldinglist.append(word.casefold())

    macsearchtermslist = []
    for word in casefoldinglist:

        casefold = hmac.new(searchkey, word.encode(
            'utf-8'), hashlib.sha256).hexdigest()
        macsearchtermslist.append(casefold)

    macsearchtermslist = list(set(macsearchtermslist))
    macsearchtermslist.sort()
    
    if any(mac_search_term in macsearchtermslist for mac_search_term in encrypted_terms):
        print(file)
        return 1

    return 0

if __name__ == "__main__":
    if not args.dec and not args.search:

        jflag = False
        if args.json:
            jflag = True
        files = args.args
        if len(files) == 0:

            sys.exit(1)
        for file in files:
            if Path(file).is_file() == False:
                sys.exit(1)

        filemetadataList = []
        fileNotEncryptedList = []
        for file in files:
            metadataname = '.fenc-meta.'+file
            if os.path.exists(metadataname) is False:
                fileNotEncryptedList.append(file)
            else:
                filemetadataList.append(file)

        if len(filemetadataList) > 0:
            print("file already encrypted", file=sys.stderr)
            sys.exit(1)

        for file in files:
            file_size = os.path.getsize(file)
            if os.path.getsize(file) < 32:
                sys.exit(1)

        password = get_password()

        outputjson = {}
        for file in fileNotEncryptedList:
            ct, outputjson = enc_file(file, password, outputjson)
            
        if jflag:
            json.dump(outputjson, sys.stdout)
        

    if args.dec:
        jflag = False
        if args.json:
            jflag = True

        files = args.args
        if len(files) == 0:
            sys.exit(1)

        for file in files:
            if Path(file).is_file() == False:
                sys.exit(1)

        filemetadataList = []
        fileNotEncryptedList = []
        for file in files:
            metadataname = '.fenc-meta.'+file
            if os.path.exists(metadataname) is False:
                fileNotEncryptedList.append(file)
            else:
                filemetadataList.append(file)

        if len(fileNotEncryptedList) > 0:
            print("file not encrypted", file=sys.stderr)
            sys.exit(1)

        for file in files:
            file_size = os.path.getsize(file)
            if os.path.getsize(file) < 32:
                sys.exit(1)


        password = get_password()

        outputjson = {}
        for file in filemetadataList:
            pt, outputjson = dec_file(file, password, outputjson)
            with open(file, 'w') as plaintextfile:
                plaintextfile.write(pt)
            plaintextfile.close()
            deletemetadatafile(file)
        if jflag:
            json.dump(outputjson, sys.stdout)

    if args.search:
        jflag = False
        if args.json:
         jflag = True

        encrypted_files = []
        search_terms = args.args
        password = get_password()
        dir_list = os.listdir()
        for each in dir_list:
            if each.startswith(".fenc-meta."):
                encrypted_files.append(each[len('.fenc-meta.'):])

        if len(encrypted_files) == 0:
            print("no encrypted file found.", file=sys.stderr)
            sys.exit(1)

        searchable_files = []
        for each in encrypted_files:
            filemetadata = getmetadatacontents(each)
            salt = filemetadata['salt']
            salt = bytes.fromhex(salt)

            masterkey = createmasterkey(password, salt)

            # # Generate the password validator and key schedule for each file, per above.
            validator, fk1, fk2, fk3, fk4, mackey, searchkey = createkeyseries(masterkey)
            feistelkeys = [fk1, fk2, fk3, fk4]
            searchterms = []
            if filemetadata["validator"] == validator.hex():
                searchable_files.append((each, searchkey))

        if len(searchable_files) == 0:
            print("No searchable file with this password", file=sys.stderr)
            sys.exit(1)

        sum = 0
        for each, searchkey in searchable_files:
            sum += search_file(search_terms, searchkey, each, jflag)

        if sum == 0:
            print('No matching keyword in any file')
            sys.exit(1)
        
