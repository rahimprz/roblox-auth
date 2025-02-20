import requests
import json
import base64
import getpass
import time
import random
from auth import BATGenerator


class Roblox2FADisabler:
    def __init__(self):
        self.session = requests.Session()
        self.user_id = None
        self.challenge_start_time = None
        self.user_agent = self.generate_user_agent()
        self.common_headers = self.generate_common_headers()

    def generate_user_agent(self):
        chrome_version = f"132.0.{random.randint(1000, 9999)}"
        return f"Mozilla/5.0 (Windows NT 10.0; {'Win64; x64' if random.choice([True, False]) else 'WOW64'}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"

    def generate_common_headers(self):
        return {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/",
            "Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Priority": "u=1, i",
            "User-Agent": self.user_agent
        }

    def get_user_id(self):
        headers = {**self.common_headers}
        response = self.session.get(
            "https://users.roblox.com/v1/users/authenticated",
            headers=headers
        )
        response.raise_for_status()
        self.user_id = response.json()["id"]
        print(f"User ID obtained: {self.user_id}")

    def initiate_challenge(self):
        url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/configuration/authenticator/disable"
        
        # Initial CSRF token request
        response = self.session.post(url, headers=self.common_headers)
        self.csrf_token = response.headers.get("x-csrf-token")
        if not self.csrf_token:
            raise Exception("CSRF token not found")

        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "Content-Type": "application/json"
        }

        response = self.session.post(url, headers=headers)
        if response.status_code != 403:
            raise Exception("Challenge initiation failed")

        # Store challenge parameters
        self.primary_challenge_id = response.headers["rblx-challenge-id"]
        self.roblox_machine_id = response.headers.get("roblox-machine-id", "")
        self.challenge_type = response.headers.get("rblx-challenge-type", "")
        
        # Decode metadata
        metadata = base64.b64decode(response.headers["rblx-challenge-metadata"]).decode()
        metadata_json = json.loads(metadata)
        self.metadata_challenge_id = metadata_json["challengeId"]
        self.action_type = metadata_json["actionType"]
        
        print("Challenge initiated successfully")
        self.challenge_start_time = time.time()

    def send_metrics(self, event_name, value, label_values):
        metrics_url = "https://apis.roblox.com/account-security-service/v1/metrics/record"
        payload = {
            "name": event_name,
            "value": value,
            "labelValues": label_values
        }
        
        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "Content-Type": "application/json",
            "roblox-machine-id": self.roblox_machine_id
        }

        response = self.session.post(metrics_url, json=payload, headers=headers)
        if not response.ok:
            print(f"Warning: Metrics event {event_name} failed")

    def verify_2fa_code(self, code):
        # Send initial metrics
        self.send_metrics("event_2sv", 1, {
            "action_type": self.action_type,
            "event_type": "Initialized",
            "application_type": "unknown"
        })
        
        self.send_metrics("event_generic", 1, {
            "event_type": "Success",
            "challenge_type": self.challenge_type
        })

        # Verify code
        verify_url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/challenges/authenticator/verify"
        payload = {
            "challengeId": self.metadata_challenge_id,
            "actionType": self.action_type,
            "code": code
        }

        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "Content-Type": "application/json",
            "roblox-machine-id": self.roblox_machine_id
        }

        response = self.session.post(verify_url, json=payload, headers=headers)
        response.raise_for_status()
        
        self.verification_token = response.json()["verificationToken"]
        print("2FA code verified successfully")

        # Calculate solve time
        solve_time = int((time.time() - self.challenge_start_time) * 1000)
        
        # Send verification metrics
        self.send_metrics("event_2sv", 1, {
            "action_type": self.action_type,
            "event_type": "VerifiedAuthenticator",
            "application_type": "unknown"
        })
        
        self.send_metrics("solve_time_2sv", solve_time, {
            "action_type": self.action_type,
            "event_type": "VerifiedAuthenticator",
            "application_type": "unknown"
        })

    def continue_challenge(self):
        continue_url = "https://apis.roblox.com/challenge/v1/continue"
        
        challenge_metadata = {
            "verificationToken": self.verification_token,
            "rememberDevice": False,
            "challengeId": self.metadata_challenge_id,
            "actionType": self.action_type
        }

        payload = {
            "challengeId": self.primary_challenge_id,
            "challengeType": self.challenge_type,
            "challengeMetadata": json.dumps(challenge_metadata)
        }

        # Generate BAT token for the payload
        payload_json = json.dumps(payload, separators=(',', ':'))
        bat_gen = BATGenerator()
        bound_auth_token = bat_gen.generate_bound_auth_token(payload_json)

        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "Content-Type": "application/json",
            "rblx-challenge-id": self.primary_challenge_id,
            "rblx-challenge-type": self.challenge_type,
            "rblx-challenge-metadata": base64.b64encode(
                json.dumps(challenge_metadata).encode()
            ).decode(),
            "roblox-machine-id": self.roblox_machine_id,
            "x-bound-auth-token": bound_auth_token  # Add BAT token
        }

        response = self.session.post(continue_url, json=payload, headers=headers)
        response.raise_for_status()
        print("Challenge continuation successful")

    def final_disable(self):
        disable_url = f"https://twostepverification.roblox.com/v1/users/{self.user_id}/configuration/authenticator/disable"
        
        final_metadata = {
            "verificationToken": self.verification_token,
            "rememberDevice": False,
            "challengeId": self.metadata_challenge_id,
            "actionType": self.action_type
        }

        # Generate BAT token for empty payload
        bat_gen = BATGenerator()
        bound_auth_token = bat_gen.generate_bound_auth_token("")

        headers = {
            **self.common_headers,
            "X-CSRF-Token": self.csrf_token,
            "Content-Type": "application/json",
            "rblx-challenge-id": self.primary_challenge_id,
            "rblx-challenge-type": self.challenge_type,
            "rblx-challenge-metadata": base64.b64encode(
                json.dumps(final_metadata, separators=(',', ':')).encode()
            ).decode(),
            "roblox-machine-id": self.roblox_machine_id,
            "x-bound-auth-token": bound_auth_token  # Add BAT token
        }

        response = self.session.post(disable_url, headers=headers)
        if response.status_code == 200:
            print("✅ 2FA disabled successfully")
        else:
            raise Exception(f"Final disable failed: {response.text}")


    def run(self, cookie, code):
        self.session.cookies[".ROBLOSECURITY"] = cookie
        try:
            self.get_user_id()
            self.initiate_challenge()
            self.verify_2fa_code(code)
            self.continue_challenge()
            self.final_disable()
        except Exception as e:
            print(f"Error: {str(e)}")
            exit(1)

if __name__ == "__main__":
    print("Roblox 2FA Disabler\n")
    disabler = Roblox2FADisabler()
    
    cookie = getpass.getpass("Enter .ROBLOSECURITY cookie: ")
    code = input("Enter 2FA code: ").strip()
    
    disabler.run(cookie, code)