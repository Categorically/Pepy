


import sys, os, base64, datetime, hashlib, hmac, urllib
import requests

# Constants
METHOD = 'POST'
HOST = "8k9jn092va.execute-api.us-east-1.amazonaws.com"
REGION = "us-east-1"
CONTENT_TYPE = 'application/json; charset=UTF-8'
PEPCOIN_APPLICATION = "web"
SIGNED_HEADERS = "content-type;host;x-amz-date;x-amz-security-token;x-pepcoin-application"
ALGORITHM = 'AWS4-HMAC-SHA256'
SERVICE = "execute-api"

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning



def create_auth(user,payload,canonical_uri):
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')

    canonical_uri = canonical_uri + "\n"
    date_stamp = t.strftime('%Y%m%d')

    canonical_headers = "content-type:" + CONTENT_TYPE + "\n" + 'host:' + HOST + '\n' + "x-amz-date:" + amz_date + '\n' + "x-amz-security-token:" + user.amz_security_token + '\n' + "x-pepcoin-application:" + PEPCOIN_APPLICATION + "\n"

    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

    canonical_string = METHOD + "\n" + canonical_uri + '\n' +  canonical_headers + '\n' +  SIGNED_HEADERS + "\n" + payload_hash
    
    credential_scope = date_stamp + "/" + REGION + "/" + SERVICE + "/" + 'aws4_request'



    string_to_sign  = ALGORITHM + "\n" + amz_date + "\n" + credential_scope + "\n" + hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()

    signing_key = getSignatureKey(user.secretkey, date_stamp, REGION, SERVICE)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = ALGORITHM + ' ' + 'Credential=' + user.accesskeyid + '/' + credential_scope + ', ' +  'SignedHeaders=' + SIGNED_HEADERS + ', ' + 'Signature=' + signature
    return [authorization_header,amz_date]


def refresh_token(amz_security_token:str):
    url = "https://cognito-idp.us-east-1.amazonaws.com/"
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/x-amz-json-1.1",
        "Referer": "https://www.pepcoin.com/",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        "X-Amz-User-Agent": "aws-amplify/0.1.x js",
        "Origin": "https://www.pepcoin.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
        }
    payload = '{"ClientId":"3pdercos1mgc9it641r8b1ktc6","AuthFlow":"REFRESH_TOKEN_AUTH","AuthParameters":{"REFRESH_TOKEN":"'+ amz_security_token +'","DEVICE_KEY":null}}'
    

    try:
        res = requests.post(url=url,headers=headers,data=payload)
    except:
        return None

    if "AccessToken" in res.text:
        AuthenticationResult = res.json().get("AuthenticationResult")
        AccessToken = AuthenticationResult.get("AccessToken")
        IdToken = AuthenticationResult.get("IdToken")
        return [AccessToken,IdToken]
    else:
        return False
    
def login_with_token(id_token:str,IdentityId:str):
    url = "https://cognito-identity.us-east-1.amazonaws.com/"
    payload = '{"Logins":{"cognito-idp.us-east-1.amazonaws.com/us-east-1_zKmReKp5r":"'+id_token+'"},"IdentityId":"'+IdentityId+'"}'
    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/x-amz-json-1.1",
        "Referer": "https://www.pepcoin.com/",
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        "X-Amz-User-Agent": "aws-amplify/2.3.0 js aws-amplify/2.3.0 js callback",
        "Origin": "https://www.pepcoin.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
    }

    try:
        res = requests.post(url=url,data=payload,headers=headers)
    except:
        return None
    if "Credentials" in res.text:
        Credentials = res.json().get("Credentials")
        AccessKeyId = Credentials.get("AccessKeyId")
        SecretKey = Credentials.get("SecretKey")
        SessionToken = Credentials.get("SessionToken")
        return [SessionToken,SecretKey,AccessKeyId]
    else:
        return False

def get_aws_id(IdToken:str):
    url = "https://cognito-identity.us-east-1.amazonaws.com/"
    payload = '{"IdentityPoolId":"us-east-1:76c07313-4129-4136-a4b9-4c167648092d","Logins":{"cognito-idp.us-east-1.amazonaws.com/us-east-1_zKmReKp5r":"'+IdToken+'"}}'
    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/x-amz-json-1.1",
        "Referer": "https://www.pepcoin.com/",
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Target": "AWSCognitoIdentityService.GetId",
        "X-Amz-User-Agent": "aws-amplify/2.3.0 js aws-amplify/2.3.0 js callback",
        "Origin": "https://www.pepcoin.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"
    }

    try:
        res = requests.post(url=url,data=payload,headers=headers)
        try:
            return res.json().get("IdentityId")
        except:
            return False
    except:
        return False

def submit_code(code,user,hcaptcha):
    url = "https://8k9jn092va.execute-api.us-east-1.amazonaws.com/production/code/submit"
    canonical_uri = "/production/code/submit"

    payload = '{"data":{"snack":{"code":["'+ code.number +'","'+ code.fourdigits[0:2] + ":" + code.fourdigits[2:]  +'","'+code.lastline+'"],"sku":"'+code.barcode+'"}},"sm_token":"' + user.SMToken + '","hcaptchaResponse":"'+hcaptcha+'"}'
    auth = create_auth(user,payload,canonical_uri)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/json; charset=UTF-8",
        "Referer": "https://www.pepcoin.com/",
        "x-amz-date": auth[1],
        "X-Amz-Security-Token": user.amz_security_token,
        "X-Pepcoin-Application": "web",
        "Authorization":auth[0],
        "Origin": "https://www.pepcoin.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"}
    try:
        res = requests.post(url=url,headers=headers,data=payload)
    except:
        print("Error connecting")
        return None
    if "Recaptcha Validation Failed" in res.text:
        print("Recaptcha Validation Failed")
    if 'statusCode":400,' in res.text:
        print("Failed to apply the code")
        return None
    if 'statusCode":409,' in res.text or 'statusCode":200,' in res.text:
        print("Code applied")
        return True
    if 'statusCode":405,' in res.text:
        print("User has reached the maximum number of daily redemptions")
        return False
    print("Unexpected return: " + str(res.status_code) + str(res.text))


def user_authorize(user):
    url = "https://8k9jn092va.execute-api.us-east-1.amazonaws.com/production/userauth/authorize"
    canonical_uri = "/production/userauth/authorize"
    payload = ""
    auth = create_auth(user,payload,canonical_uri)
    headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/json; charset=UTF-8",
            "Referer": "https://www.pepcoin.com/",
            "x-amz-date": auth[1],
            "X-Amz-Security-Token": user.amz_security_token,
            "X-Pepcoin-Application": "web",
            "Authorization":auth[0],
            "Origin": "https://www.pepcoin.com",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site"}
    try:
        res =requests.post(url=url,headers=headers,data=payload)
    except:
        return False
    try:
        result = res.json().get("result")
        if result == None:
            return False
    except:
        return False
    result_user = result.get("user")
    user.SMToken = result.get("token")
    user.points = result_user.get("points")
    user.suspended = result_user.get("suspended")
    return user

def validate_snack(code,user):
    url = "https://8k9jn092va.execute-api.us-east-1.amazonaws.com/production/code/validate/snack"
    canonical_uri = "/production/code/validate/snack"
    payload = '{"scanData":["'+code.number+'","'+code.lastline+'","'+code.fourdigits+'"],"sm_token":"v2--nF8jcIcGIqasNKdPSHouet6RnS6XI7dAIyFd10g_qUo=--_bnI6LgRniSiN_T-OJ7vXOl8SLsCVZrMk5GYhaJKPVMSkrIG_Xu8_UCtmSTGBY3zSg==","strict":true}'
    auth = create_auth(user,payload,canonical_uri)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "application/json; charset=UTF-8",
        "Referer": "https://www.pepcoin.com/",
        "x-amz-date": auth[1],
        "X-Amz-Security-Token": user.amz_security_token,
        "X-Pepcoin-Application": "web",
        "Authorization":auth[0],
        "Origin": "https://www.pepcoin.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site"}
    try:
        res = requests.post(url=url,headers=headers,data=payload)
    except:
        return None
    print(res.text)