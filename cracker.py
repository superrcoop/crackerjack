#!/usr/bin/python

"""Crackerjack

Usage: 
    crackerjack.py <plaintext_password>
    crackerjack.py (-m | --medium) <medium_plaintext_password>...
    crackerjack.py (-d | --difficult) <hard_plaintext_password>...
    crackerjack.py (-f | --file) <path/to/password_list.txt> 
    crackerjack.py (-h | --help)
    crackerjack.py (-v | --version)

Options:
    -h --help       Show this screen.
    -v --version    Show version.
    -m --medium     Password can be alphanumeric with atleast 1 upper and\or 
                    lowercase letter. e.g  -m Password123.
    -d --difficult  Password must be of length 8, contain at least 1 upper,
                    lower alphanumeric character and a special character 
                    (a-z,A-Z,0-9,!@#\$%\^&) e.g -d P@ssw0rd#% .
    -f --file       Accepts a file with a list of passwords e.g. -f /path/to/password_list.txt.

"""
import timeit
import json,os,sys
import random
import bcrypt
from docopt import docopt
from re import compile

CHAR = "1234567890!@#$%^&*"
HARD_REGEX = compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&])(?=.{8,})')
MEDIUM_REGEX = compile(r'^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})')

def hash_password(plain_password):
    return hashpw(plain_password,bcrypt.gensalt())

def regexPassword(password): 
    if not PASSWORD_REGEX.match(password): 
        return False
    return True

def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print '%r  %2.2f ms' % \
                  (method.__name__, (te - ts) * 1000)
        return result
    return timed

def load_words(salt):
    #load words from .json and create hash_words.txt file
    try:
        filename = os.path.dirname(sys.argv[0])+"words_dictionary.json"
        with open(filename,"r") as english_dictionary:
            valid_words = json.load(english_dictionary)
            #hash dictionary words
            ff=open("hash_words.txt","a+")
            for key in valid_words:
                hash_key=crypt.crypt(key, salt)
                ff.write(hash_key+"\n")
            ff.close()
    except Exception as e:
        logging.exception("message")

def comparepwd():
    #compare hash passwords with hash dictionary
    with open("hash_words.txt") as h1, open("passwords.txt") as h2:
        words=set(h1.read().split())
        for line in h2:
            if line in words:
                print "Match found: "+line
                return line
    print "Match not found"
    return 0
     
@timeint
def main():
    arguments = docopt(__doc__, version='Crackerjack 2.0')
if __name__ == '__main__':

    main()
    
    
    """load_words(salt)
    entered_pw_hash = crypt.crypt(raw_input('Type a password: '), salt)
    try:
        f= open("passwords.txt","a+")
        f.write(entered_pw_hash+"\n")
    except Exception as e:
        return str(e)
    comparepwd()
    f.close()"""
