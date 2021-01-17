from warrant.aws_srp import AWSSRP
import boto3
from botocore.config import Config
from AWS import login_with_token,refresh_token,get_aws_id,user_authorize,submit_code
import botocore.session


class user:
    def __init__(self,amz_security_token,secretkey,accesskeyid,SMToken=None,EmailAddress=None):
        self.amz_security_token = amz_security_token # AUTH
        self.secretkey = secretkey # Used for signing the requests
        self.accesskeyid = accesskeyid # AUTH
        self.SMToken = SMToken # Used for sumbitting codes
        self.points = 0
        self.suspended = False
    def __repr__(self):
        
        return str(self.__dict__)
class code:
    def __init__(self,number,lastline,fourdigits,barcode):
        self.number = number
        self.lastline = lastline
        self.fourdigits = fourdigits
        self.barcode = barcode
    def __repr__(self):
        return str(self.__dict__)
        
def login(combo):
    try:
        username,password = combo.split(":",1)
        username = username.lower()
    except:
        return False

    session = botocore.session.get_session()
    CLIENT = session.create_client('cognito-idp', config=Config(region_name="us-east-1"))

    POOL_ID = 'us-east-1_zKmReKp5r'
    CLIENT_ID = '3pdercos1mgc9it641r8b1ktc6'
    try:
        aws = AWSSRP(username=username, password=password, pool_id=POOL_ID,
                    client_id=CLIENT_ID,client=CLIENT)
    except:
        return False
    try:
        tokens = aws.authenticate_user(client=CLIENT).get("AuthenticationResult")
    except:
        return False

    if tokens:
        IdentityId = get_aws_id(tokens.get("IdToken"))
        if IdentityId:
            return login_with_token(tokens.get("IdToken"),IdentityId)
        else:
            return False
    else:
        return False

if __name__ == "__main__":
    hcaptcha = "HCAPTCHA TOKEN" # Needed for submiting codes only
    new_code = code("123456789","12","1234","123456789123")
    new_user = login("USERNAME:PASSWORD")
    if new_user:
        amz_security_token = new_user[0]
        secretkey = new_user[1]
        accesskeyid = new_user[2]

        new_user = user(amz_security_token,secretkey,accesskeyid)
        # Get user SM token and some user information
        new_user = user_authorize(new_user)
        if not new_user.suspended:

            submit_code(new_code,user,hcaptcha)
