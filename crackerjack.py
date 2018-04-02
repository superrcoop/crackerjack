#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
                    lowercase letter and atleast 6 characters long. e.g  -m Pencil1.
    -d --diff       Password must be of length 9, contain at least 1 upper,
                    lower alphanumeric character and a special character 
                    (a-z,A-Z,0-9,!@#\$%\^&) e.g -d P@ssw0rd#% .
    -f --file       Accepts a file with a list of passwords e.g. -f /path/to/password_list.txt.

"""
import logging,time
import json,os,sys
import bcrypt
from docopt import docopt
from re import compile
from time import sleep

#Commonly used regex for accepting passwords across websites forms
HARD_REGEX = compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&])(?=.{9,})')
MEDIUM_REGEX = compile(r'^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})')

def hard_regex(password): 
    if HARD_REGEX.match(password): 
        return True
    return False

def medium_regex(password): 
    if MEDIUM_REGEX.match(password): 
        return True
    return False

def hash_password(plain_password):
    return bcrypt.hashpw(plain_password,bcrypt.gensalt())

def check_password(password,hashed):
    if bcrypt.checkpw(password,hashed):
        return True
    return False

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
            print '\nTime taken in module %r = %2.2f ms' % \
                  (method.__name__, (te - ts) * 1000)
        return result
    return timed

def load_m_words():
    """Fetches words from a simple word dictionary.

    Files contains dictionary words plus some of the most common passwords 
    captured from rockyou. No string manipulation occured. 
    Only for words matching the simplest regular expression. 

    Returns:
        A text file with hashed words from the dictionary
    """
    try:
        filename = os.getcwd()+"/data/words_dictionary.json"
        with open(filename,"r") as easy_password_dictionary:
            valid_words = json.load(easy_password_dictionary)
            return valid_words
    except Exception as e:
        logging.exception("message")
        print str(e)
    finally:
        ff.close()

def load_h_words():
    """Fetches words from a simple word dictionary.

    Files contains dictionary words plus some of the most common passwords 
    captured from rockyou. No string manipulation occured. 
    Only for words matching the simplest regular expression. 

    Returns:
        A text file with hashed words from the dictionary
    """
    try:
        filename = os.getcwd()+"/data/words_dictionary.json"
        with open(filename,"r") as easy_password_dictionary:
            valid_words = json.load(easy_password_dictionary)
            return valid_words
    except Exception as e:
        logging.exception("message")
        print str(e)
    finally:
        ff.close()

def progress(count, total, status='Attempting to crack password'):
    """Print a progress bar while password if being cracked
  
    """
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '█' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s ... %s\r' % (bar, percents, '%', status))
    if count == total:
        sys.stdout.write('\n')
    sys.stdout.flush()
   

def load_e_words():
    """Fetches words from a simple word dictionary.

    Files contains dictionary words plus some of the most common passwords 
    captured from rockyou. No string manipulation occured. 
    Only for words matching the simplest regular expression. 

    Returns:
        A text file with hashed words from the dictionary
    """
    valid_words=[]
    filename = os.getcwd()+"/data/samplewords.txt"
    try:
        with open(filename,"r") as easy_password_dictionary:
            for line in easy_password_dictionary:
                valid_words.append(line.strip('\n'))
            return valid_words
    except Exception as e:
        logging.exception("message")
        print str(e)

def comparepwd(hash_password,dictionary):
    """Compare hashed_password with dictionary of passwords

    These words a dictionary words plus some of the most common passwords 
    captured from rockyou and websters-dictionary. No string manipulation occured. 
    Only for words matching the simplest regular expression. 

    Returns:
        If identified returns the plaintext word for the hash else, not found. 
    """
    total=100
    i=0
    while i < total:
        progress(i, total)
        for word in dictionary:
            i+=1
            if hash_password==word:
                print "Match found , password_hash = "+hash_password+" = "+word

        
@timeit
def main(args):
    if args['<plaintext_password>']:
        plaintext_passwords=args['<plaintext_password>']
        for password in plaintext_passwords:
            if hard_regex(password):
                dictionary=load_h_words()
                entered_pw_hash = hash_password(password)
                comparepwd(entered_pw_hash,dictionary)
            elif medium_regex(password):
                dictionary=load_m_words()
                entered_pw_hash = hash_password(password)
                comparepwd(entered_pw_hash,dictionary)
            else:
                dictionary=load_e_words()
                entered_pw_hash = hash_password(password)
                comparepwd(entered_pw_hash,dictionary)

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
  
    return

if __name__ == '__main__':
    args = docopt(__doc__, version='Crackerjack 2.0')
    main(args)
    
    

 
