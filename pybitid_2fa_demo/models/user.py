'''
A very basic model for user entities
'''
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


class User(object):
    
    def __init__(self, login, password, email):
        '''
        Constructor
        Parameters:
            login     = user login
            password  = user password
            email     = user email
        '''
        self.login = login
        self.email = email
        # Salts and hashes the password
        self.set_password(password)
        # Initializes the uid
        self.uid = str(uuid.uuid4())
        # Initializes an empty 2FA address
        self.address = None
        # Sets some additional attributes
        self.created = datetime.now()
        self.signin_count = 0
        
    
    def set_tfa_address(self, address):
        '''
        Sets bitcoin address used for 2FA
        Parameters:
            address = bitcoin address
        '''
        self.address = address
        
        
    def get_tfa_address(self):
        '''
        Return the bitcoin address used for 2FA or None if 2FA is not activated
        '''
        return self.address if self.tfa_activited() else None
            
        
    def tfa_activited(self):
        '''
        Checks if 2FA is activated for this account
        '''
        return True if self.address else False
    
    
    def set_password(self, password):
        '''
        Salts and hashes a password
        Parameters:
            password = password to process
        '''
        self._pw_hash = generate_password_hash(password)


    def check_password(self, password):
        '''
        Checks if given password matches a given password
        Parameters:
            password = password to process
        '''
        return check_password_hash(self._pw_hash, password)
    
    