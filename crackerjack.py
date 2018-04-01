#!/usr/bin/python

"""Crackerjack

Usage: 
    crackerjack.py <plaintext_password>...
    crackerjack.py (-b) [-m ] [-d ] <hashed_password>...
    crackerjack.py (-f | --file) [-b] <path/to/password_list.txt>
    crackerjack.py (-h | --help)
    crackerjack.py (-v | --version)

Options:
    -h --help       Show options.
    -v --version    Show version.
    -b              Indicates a bcrypt hash password       
    -m --med        Password can be alphanumeric with atleast 1 upper and\or 
                    lowercase letter. e.g  -m Password123.
    -d --diff       Password must be of length 8, contain at least 1 upper,
                    lower alphanumeric character and a special character 
                    (a-z,A-Z,0-9,!@#\$%\^&) e.g -d P@ssw0rd#% .
    -f --file          Accepts a file with a list of passwords e.g. -f /path/to/password_list.txt.

"""
import logging
import time
import json,os,sys
import random
import bcrypt
from docopt import docopt
from re import compile

CHAR = "1234567890!@#$%^&*"
HARD_REGEX = compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&])(?=.{8,})')
MEDIUM_REGEX = compile(r'^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})')

def hash_password(plain_password):
    return bcrypt.hashpw(plain_password,bcrypt.gensalt())

def hardPassword(password): 
    if not HARD_REGEX.match(password): 
        return False
    return True

def mediumPassword(password): 
    if not MEDIUM_REGEX.match(password): 
        return False
    return True

def check_password(password,hashed):
    if bcrypt.checkpw(password,hashed):
        print "Match Found"
    else:
        print "No Matched Found"

def verify_hash(hash):
    """The prefix "$2a$" or "$2b$" (or "$2y$") 
    in a hash string in a shadow password file 
    indicates that hash string is a bcrypt hash 
    in modular crypt format."""
    return

def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print 'Time taken in module %r = %2.2f ms' % \
                  (method.__name__, (te - ts) * 1000)
        return result
    return timed

def load_m_words():
    #load medium regex dic passwords
    return

def load_h_words():
    #load medium regex dic passwords
    return

def load_e_words(inputfile=None):
    #load words from .json and create hash_words.txt file
    try:
        filename = os.path.dirname(sys.argv[0])+"data/words_dictionary.json"
        with open(filename,"r") as english_dictionary:
            valid_words = json.load(english_dictionary)
            #hash dictionary words
            ff=open("hash_words.txt","a+")
            for key in valid_words:
                hash_key=hash_password(key.encode('utf-8'))
                ff.write(hash_key+"\n")
            ff.close()
    except Exception as e:
        logging.exception("message")

def comparepwd():
    #compare hash passwords with hash dictionary
    with open("data/hash_words.txt") as h1, open("data/passwords.txt") as h2:
        words=set(h1.read().split())
        for line in h2:
            if line in words:
                print "Match found: "+line
                return line
    print "Match not found"
    return 0

@timeit
def main(args):
    if args['<plaintext_password>']:
        load_e_words()
        plaintext_password=args['<plaintext_password>']
        if len(plaintext_password)>1:
            print "List of words"
        else:
            entered_pw_hash = hash_password(plaintext_password[0])
            try:
                f= open("passwords.txt","a+")
                f.write(entered_pw_hash+"\n")
            except Exception as e:
                logging.exception("message")
                print str(e)
            finally:
                comparepwd()
                f.close()
    if args['-b']:
    #hash pasword cracker algorightm
        if args['--med']:
            return
        if args['--diff']:
            return
        
        return
    if args['--file']:
        if args['-b']:
            return
        return
    

        #plaintext pasword input file
    """load_words(salt)
    entered_pw_hash = crypt.crypt(raw_input('Type a password: '), salt)
    try:
        f= open("passwords.txt","a+")
        f.write(entered_pw_hash+"\n")
    except Exception as e:
        return str(e)
    comparepwd()
    f.close()"""
    return
    


if __name__ == '__main__':
    args = docopt(__doc__, version='Crackerjack 2.0')
    print args
    main(args)
 
