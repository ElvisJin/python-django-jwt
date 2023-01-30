import time
from jose import jwt, jws
import requests

slapi = ""

class JWTPayload:
    def __init__(self, headers, claims, signing_input=None, signature=None):
        self.headers = headers
        self.claims = claims
        self.signing_input = signing_input
        self.signature = signature

    @classmethod
    def from_string(cls, str):
        return cls(*jws._load(str))


class ShortLetsAPI:
    def __init__(self, settings):
        self.endpoint = settings.get(
            "endpoint", "https://api.klevio.com/sl/v1/rpc")
        self.key_id = settings.get("external_id")
        self.client_id = settings.get("client_id")
        self.my_private_key = settings.get("my_private_key")
        self.others_public_key = settings.get("others_public_key")

    def api_operation_payload(self, method, params):
        now = int(time.time())
        rpc_id = int(time.time() * 100000)
        rpc = {
            "id": rpc_id,
            "method": method,
            "params": params
        }
        jwt_headers = {
            "alg": "ES256",
            "typ": "JWT",
            "kid": self.key_id
        }
        jwt_payload = {
            "iss": self.client_id,
            "aud": "klevio-api/v1",
            "iat": now,
            "jti": "jti-{}".format(now),
            "exp": now + 30,
            "rpc": rpc
        }

        # print("BEFORE-----", jwt_payload , "->>>> ,, ", type(jwt_payload))

        return JWTPayload(jwt_headers, jwt_payload)

    def key_operation_payload(self, method, key_id):
        return self.api_operation_payload(method, {"key": key_id})

    def call(self, jwt_payload):
        # print("IT'S HEREEE" , jwt_payload.claims ,"<<<--->>>", jwt_payload.headers)
        jwt_content = jwt.encode(
            jwt_payload.claims, self.my_private_key, "ES256", jwt_payload.headers)
        # print("JWT", jwt_content)
        http_headers = {
            "X-KeyID": self.key_id,
            "Content-Type": "application/jwt"
        }
        try:
            # print("#####---->>>>>>", self.endpoint, "<<--->>", http_headers , "<<-->>", jwt_content)
            # jwt_content = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlAxQzMyRlY1OVhSOERLOU1GWDc0TTUwUFo5TUVBWjMyOU5USkdFM0hNQSJ9.eyJpc3MiOiJDNEZWWTFGTVlXVzYwSzA1RjhOUzkxQTJKREZBUEEiLCJhdWQiOiJrbGV2aW8tYXBpL3YxIiwiaWF0IjoxNjc1MDM1NzY4LCJqdGkiOiJqdGktMTY3NTAzNTc2OCIsImV4cCI6MTY3NTAzNTc3MywicnBjIjp7ImlkIjoxNjc1MDM1NzY4MDc3MTMuODgsIm1ldGhvZHMiOiJncmFudEtleSIsInBhcmFtcyI6eyJzb3VyY2UiOnsiJHR5cGUiOiJwcm9wZXJ0eSIsImlkIjoiTWFpbkdhdGVDZWRhckhvbGxvdyJ9LCJ1c2VyIjp7IiR0eXBlIjoidXNlciIsImVtYWlsIjoiZmFtaWx5QHJvbWFoaS5jb20ifSwidmFsaWRpdHkiOnsiZnJ'
            response = requests.post(
                self.endpoint, headers=http_headers, data=jwt_content)
            print("RESPONSE", response.content)
        except Exception as ex:
            #logger.error("Error fetching data from SL API with {}: {}".format(jwt_content, traceback.format_exc()))
            # raise Exception("Upstream error")
            return {"error":True,"message":"Upstream error 1"}
        if response.status_code == 200:
            jwt_response = response.text
            # print("HEREEEEEE----",jwt_response)
            try:
                jwt_response_object = jwt.decode(
                    jwt_response, self.others_public_key, "ES256")
                jwt_payload = JWTPayload.from_string(jwt_response)
                return (jwt_response_object["rpc"]["result"], jwt_payload)
            except Exception as ex:
                #logger.error("Error decoding SL API data: {}".format(traceback.format_exc()))
                return {"error":True,"message":"Upstream error 2"}
                # raise Exception()
        else:
            body = response.text
            # print("HEREEEEEE----",body)
            try:
                body = jwt.decode(
                    response.text, self.others_public_key, "ES256")
            except Exception as ex:
                print(ex)
                pass
            print("Upstream error (code={}, body={})".format(
                response.status_code, body))
            return {"error":True,"message":body["rpc"]["error"]["message"]}
            
            # raise Exception("Upstream error (code={}, body={})".format(
            #     response.status_code, body))


    def read_perms_key(self, perms_key_id):
        jwt_payload = self.key_operation_payload("getKey", perms_key_id)
        res, _ = yield self.call(jwt_payload)
        return res

    def delete_perms_key(self, perms_key_id):
        jwt_payload = self.key_operation_payload("deleteKey", perms_key_id)
        res, _ = yield self.call(jwt_payload)
        return res

    def grant_key(self, propertyId, email, valid_from=None, valid_to=None):
        validity = {"from": valid_from}
        if valid_to:
            validity["to"] = valid_to
        return slapi.call(slapi.api_operation_payload("grantKey", {"source": {"$type": "property", "id": propertyId},
                                                                   "user": {"$type": "user", "email": email},
                                                                   "validity": validity}))


def keyEnable():
    global slapi
    slapi = ShortLetsAPI({
        "endpoint": "https://api.klevio.com/sl/v1/rpc",
        # 'endpoint': 'http://localhost/enable_copy/response.php',
        "external_id": "P1C32FV59XR8DK9MFX74M50PZ9MEAZ329NTJGE3HMA",
        "client_id": "C4FVY1FMYWW60K05F8NS91A2JDFAPA",
        "my_private_key": """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICiySHKRnum6j4bqCnB2EPRoqEFMY6C96qucfMfiw+8loAoGCCqGSM49
AwEHoUQDQgAEh4zrdxjdHYESXePAJJGkQ4yJXsJyftVFn0Y45MsPEM+y38S8be6j
+eDNXRB9VQGvuX3ONopgxsBTGXaicOmciQ==
-----END EC PRIVATE KEY-----
""",
        "others_public_key": """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq5YAUxJ8BePUBVrxEhXJkFwGNuxM
XCV2mfyFtrwlexnf3+kWPmY6dQDPWBT+G5oeVWfCIstmuGJEZGN2cSXDAw==
-----END PUBLIC KEY-----""",
    })


    Email = "family@romahi.com"
    checkin = "2023-06-04T16:00:00Z"
    checkout = "2023-06-08T10:30:00Z"
    ret1 = slapi.grant_key("MainGateCedarHollow", Email, checkin, checkout)
    print(ret1)
