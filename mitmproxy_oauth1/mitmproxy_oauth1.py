from hashlib import sha1
from urllib.parse import quote_plus, urlparse, urlencode
from urllib import parse
import base64
import hmac
import oauthlib.oauth1.rfc5849.signature as oauth
import random
import string
import time
import urllib3

'''
mitmproxy_oauth1.py
Tested with Mitmproxy v6.0.2 using Python 3.8.2 / OpenSSL 1.1.1i (8 Dec 2020) on macOS-11.2.3-x86_64-i386-64bit

Install required packages using: pip3 install -r requirements.txt

Usage:
    mitmproxy -p <listen port> -s mitmproxy_oauth1.py 
    OR
    mitmdump -p <listen port> -s mitmproxy_oauth1.py

To test that Authorization header is really added to the original request, an upstream proxy server can be used to intercept / forward the requests:
   mitmdump -p <listen port> -s mitmproxy_oauth1.py --mode upstream:<proxy server ip:port> --ssl-insecure
   e.g.
   mitmdump -p 8090 -s mitmproxy_oauth1.py --mode upstream:http://127.0.0.1:8091 --ssl-insecure
'''

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure which hosts should get an Authorization (OAuth) header added to the original request 
target_hosts = [
    "CHANGE_ME"
]

# Specifiy user token/secret and consumer key/secret.
user_token = "CHANGE_ME"
user_secret = "CHANGE_ME"

consumer_key = "CHANGE_ME"
consumer_secret = "CHANGE_ME"


def gen_auth_header(flow, consumer_key, consumer_secret, user_token, user_secret):
    signature_char_blacklist = []
    content_type = None if 'Content-Type' not in flow.request.headers else flow.request.headers['Content-Type']

    invalid_signature = True
    while invalid_signature:
        nonce = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(16))
        timestamp = int(time.time())

        auth_header = {
            "Authorization":
                ('OAuth oauth_consumer_key="%s", '
                    'oauth_token="%s", '
                    'oauth_signature_method="HMAC-SHA1", '
                    'oauth_timestamp="%d", '
                    'oauth_nonce="%s", '
                    'oauth_version="1.0"') % (consumer_key, user_token, timestamp, nonce)
        }

        if content_type and 'multipart/form-data' in content_type:
            # Exclude collecting body parameters for multipart form posts
            # https://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
            params = oauth.collect_parameters(
                uri_query=urlencode(parse.parse_qsl(
                    urlparse(flow.request.url).query)),
                headers=auth_header,
                exclude_oauth_signature=True,
                with_realm=False
            )
        else:
            params = oauth.collect_parameters(
                uri_query=urlencode(parse.parse_qsl(
                    urlparse(flow.request.url).query)),
                body=urlencode(flow.request.content.decode()),
                headers=auth_header,
                exclude_oauth_signature=True,
                with_realm=False
            )

        # Generate the signature base string from method, request URI, and params
        # https://tools.ietf.org/html/rfc5849#section-3.4.1.1
        base_str = oauth.signature_base_string(
            flow.request.method,
            oauth.base_string_uri(flow.request.url),
            oauth.normalize_parameters(params)
        )

        hmac_key = str.encode("%s&%s" % (consumer_secret, user_secret))
        hmac_text = str.encode(base_str)

        # Calculate an HMAC-SHA1 Signature from the signature base string and secrets
        # https://tools.ietf.org/html/rfc5849#section-3.4.2
        sig_hash = hmac.new(hmac_key, hmac_text, sha1).digest()
        sig_str = base64.b64encode(sig_hash).decode().rstrip("\n")
        
        # Invalid Signature if sig_str contains any blacklisted characters
        invalid_signature = len(signature_char_blacklist) > 1 and not any(c in sig_str for c in signature_char_blacklist)
    
    auth_header['Authorization'] += (
            ', oauth_signature="%s"' % quote_plus(sig_str))
    return auth_header

def request(flow):
    global consumer_key, consumer_secret, user_token, user_secret
    if flow.request.host in target_hosts:
        auth_header = gen_auth_header(
            flow, consumer_key, consumer_secret, user_token, user_secret)
        flow.request.headers['Authorization'] = auth_header['Authorization']
