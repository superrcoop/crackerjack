CrackerJack Hacking Tool
=======================

Python bcrypt Hybrid + dictionary password cracking tool

Getting Started !
-------------------

Clone the repository:

`$ git clone https://github.com/superrcoop/crackerjack.git`

Go into the repository:

`$ cd crackerjack`

Install dependencies:

`$ pip install -r requirements.txt`


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
    -f --file       Accepts a file with a list of passwords e.g. -f /path/to/password_list.txt.
