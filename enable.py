import requests
import json
import base64
import getpass
import time
import pyotp  # Added for TOTP generation
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from auth import BATGenerator

class Roblox2FAEnabler:
    def __init__(self):
        self.session = requests.Session()
        self.user_id = None
        self.csrf_token = None
        self.challenge_id = None
        self.challenge_type = None
        self.reauth_token = None
        self.setup_token = None
        self.manual_entry_key = None
        self.user_agent = self.generate_user_agent()
        self.common_headers = self.generate_common_headers()

    def generate_user_agent(self):
        import random
        chrome_version = f"132.0.{random.randint(1000, 9999)}"
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"

    def generate_common_headers(self):
        return {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/",
            "Sec-Ch-Ua": '"Chromium";v="132", "Google Chrome";v="132", "Not-A.Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Priority": "u=1, i",
            "User-Agent": self.user_agent
        }

    def get_user_id(self):
        response = self.session.get(
            "https://users.roblox.com/v1/users/authenticated",
            headers=self.common_headers
        )
        response.raise_for_status()
        self.user_id = response.json()["id"]
        print(f"User ID obtained: {self.user_id}")

    def get_csrf_token(self):
        url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/configuration/authenticator/enable"
        response = self.session.post(url, headers=self.common_headers)
        self.csrf_token = response.headers.get("x-csrf-token")
        if not self.csrf_token:
            raise Exception("Failed to obtain CSRF token")
        print("CSRF token obtained")

    def send_metrics(self):
        metrics_url = "https://apis.roblox.com/account-security-service/v1/metrics/record"
        payload = {
            "name": "event_generic",
            "value": 1,
            "labelValues": {
                "event_type": "Success",
                "challenge_type": "reauthentication"
            }
        }
        
        bat_gen = BATGenerator()
        payload_json = json.dumps(payload, separators=(',', ':'))
        bound_auth_token = bat_gen.generate_bound_auth_token(payload_json)
        
        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "x-bound-auth-token": bound_auth_token
        }
        
        self.session.post(metrics_url, json=payload, headers=headers)

    def initiate_enable(self):
        url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/configuration/authenticator/enable"
        
        bat_gen = BATGenerator()
        bound_auth_token = bat_gen.generate_bound_auth_token("")
        
        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "x-bound-auth-token": bound_auth_token
        }
        
        response = self.session.post(url, headers=headers)
        
        if response.status_code != 403:
            raise Exception(f"Unexpected response. Expected 403, got {response.status_code}")

        self.challenge_id = response.headers.get("rblx-challenge-id")
        metadata_b64 = response.headers.get("rblx-challenge-metadata")
        self.challenge_type = response.headers.get("rblx-challenge-type")

        missing = []
        if not self.challenge_id: missing.append("rblx-challenge-id")
        if not metadata_b64: missing.append("rblx-challenge-metadata")
        if not self.challenge_type: missing.append("rblx-challenge-type")
        if missing:
            raise Exception(f"Missing required headers: {', '.join(missing)}")

        try:
            decoded_metadata = base64.b64decode(metadata_b64).decode()
            self.challenge_metadata = json.loads(decoded_metadata)
            self.available_types = self.challenge_metadata.get("availableTypes", [])
        except Exception as e:
            raise Exception(f"Metadata decode failed: {str(e)}")

        print(f"Available auth types: {self.available_types}")

    def handle_password_reauth(self):
        password = getpass.getpass("Enter account password: ")
        generate_url = "https://apis.roblox.com/reauthentication-service/v1/token/generate"
        payload = {"password": password}
        
        bat_gen = BATGenerator()
        payload_json = json.dumps(payload, separators=(',', ':'))
        bound_auth_token = bat_gen.generate_bound_auth_token(payload_json)
        
        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "x-bound-auth-token": bound_auth_token
        }
        
        response = self.session.post(generate_url, json=payload, headers=headers)
        response.raise_for_status()
        self.reauth_token = response.json().get("token")

    def continue_challenge(self):
        continue_url = "https://apis.roblox.com/challenge/v1/continue"
        challenge_metadata = {"reauthenticationToken": self.reauth_token}
        
        payload = {
            "challengeId": self.challenge_id,
            "challengeType": self.challenge_type,
            "challengeMetadata": json.dumps(challenge_metadata)
        }
        
        bat_gen = BATGenerator()
        payload_json = json.dumps(payload, separators=(',', ':'))
        bound_auth_token = bat_gen.generate_bound_auth_token(payload_json)
        
        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "x-bound-auth-token": bound_auth_token
        }
        
        response = self.session.post(continue_url, json=payload, headers=headers)
        response.raise_for_status()

    def finalize_enable(self):
        url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/configuration/authenticator/enable"
        challenge_metadata = {"reauthenticationToken": self.reauth_token}
        metadata_b64 = base64.b64encode(json.dumps(challenge_metadata).encode()).decode()
        
        bat_gen = BATGenerator()
        bound_auth_token = bat_gen.generate_bound_auth_token("")
        
        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "rblx-challenge-id": self.challenge_id,
            "rblx-challenge-type": self.challenge_type,
            "rblx-challenge-metadata": metadata_b64,
            "x-bound-auth-token": bound_auth_token
        }
        
        response = self.session.post(url, headers=headers)
        response.raise_for_status()
        
        setup_info = response.json()
        self.setup_token = setup_info["setupToken"]
        self.manual_entry_key = setup_info["manualEntryKey"]
        
        print("\nInitial setup successful!")
        print(f"Setup Token: {self.setup_token}")
        print(f"Manual Entry Key: {self.manual_entry_key}")

    def complete_2fa_enable(self):
        # Generate TOTP code automatically
        totp = pyotp.TOTP(self.manual_entry_key)
        code = totp.now()
        print(f"Generated 2FA code: {code}")

        # Get server nonce
        nonce_response = self.session.get(
            "https://apis.roblox.com/hba-service/v1/getServerNonce",
            headers=self.common_headers
        )
        nonce_response.raise_for_status()
        
        # Debugging: Print the response content
        print("Server Nonce Response:", nonce_response.text)

        # Parse the response
        try:
            server_nonce_data = nonce_response.json()
            server_nonce = server_nonce_data.get("serverNonce") if isinstance(server_nonce_data, dict) else server_nonce_data
        except Exception as e:
            raise Exception(f"Failed to parse server nonce response: {str(e)}")

        if not server_nonce:
            raise Exception("Server nonce not found in response")

        # Generate ECDSA key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Export public key in SPKI format
        public_key_spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_public_key = base64.b64encode(public_key_spki).decode()

        # Get current timestamp
        client_epoch_timestamp = int(time.time())

        # Generate SAI signature
        data_to_sign = f"{client_public_key}:{client_epoch_timestamp}:{server_nonce}"
        signature = private_key.sign(
            data_to_sign.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        sai_signature = base64.b64encode(signature).decode()

        # Prepare payload with correct structure
        final_url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/configuration/authenticator/enable-verify"
        payload = {
            "code": code,
            "setupToken": self.setup_token,
            "secureAuthenticationIntent": {
                "clientPublicKey": client_public_key,
                "clientEpochTimestamp": client_epoch_timestamp,
                "serverNonce": server_nonce,
                "saiSignature": sai_signature
            }
        }

        # Generate BAT for final enable
        bat_gen = BATGenerator()
        payload_json = json.dumps(payload, separators=(',', ':'))
        bound_auth_token = bat_gen.generate_bound_auth_token(payload_json)

        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "x-bound-auth-token": bound_auth_token
        }

        response = self.session.post(final_url, json=payload, headers=headers)
        response.raise_for_status()
        print("\n✅ 2FA successfully enabled!")

    def run(self, cookie):
        self.session.cookies[".ROBLOSECURITY"] = cookie
        try:
            self.get_user_id()
            self.get_csrf_token()
            self.initiate_enable()
            self.send_metrics()
            
            if "Password" in self.available_types:
                self.handle_password_reauth()
            else:
                raise Exception("No supported authentication methods available")
            
            self.continue_challenge()
            self.finalize_enable()
            self.complete_2fa_enable()
            
        except Exception as e:
            print(f"Error: {str(e)}")
            exit(1)

if __name__ == "__main__":
    print("Roblox 2FA Enabler\n")
    enabler = Roblox2FAEnabler()
    cookie = getpass.getpass("Enter .ROBLOSECURITY cookie: ")
    enabler.run(cookie)