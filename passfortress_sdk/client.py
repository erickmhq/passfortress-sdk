import json

import requests

from .decorators import refresh_token_on_expiry


class PassfortressClient:

    HELLO = "hello"
    REQUEST_TOKEN = "request_token"
    REFRESH_TOKEN = "refresh_token"
    GET_SECRET = "get_secret"
    GET_SECRETS = "get_secrets"
    ADD_SECRET = "add_secret"
    ACCEPT_SHARED_SECRET = "accept_shared_secret"
    GET_CONTAINERS = "get_containers"
    ADD_CONTAINER = "add_container"
    UPDATE_CONTAINER = "update_container"
    UPDATE_SECRET = "update_secret"
    DUPLICATE_SECRET = "duplicate_secret"
    SHARE_SECRET = "share_secret"

    ENDPOINTS_URLS = {
        HELLO: "api/api-hello/",
        REQUEST_TOKEN: "api/api-auth_request-token/",
        REFRESH_TOKEN: "api/api-auth-refresh-token/",
        GET_SECRET: "api/api-get-secret/",
        GET_SECRETS: "api/api-get-secrets/",
        ADD_SECRET: "api/api-add-secret/",
        ACCEPT_SHARED_SECRET: "api/api-accept-shared-secret/",
        GET_CONTAINERS: "api/api-get-containers/",
        ADD_CONTAINER: "api/api-add-container/",
        UPDATE_SECRET: "api/api-update-secret/",
        DUPLICATE_SECRET: "api/api-duplicate-secret/",
        SHARE_SECRET: "api/api-share-secret/",
    }

    def __init__(self, api_key, secret_key, master_key, host="app.passfortress.com"):
        self.api_key = api_key
        self.secret_key = secret_key
        self.master_key = master_key
        self.host = host
        self.base_url = self._build_base_url()
        self.access_token = self._auth_request_token()

    def _build_base_url(self):
        protocol = "http"
        if self.host.endswith("passfortress.com"):
            protocol = "https"
        base_url = f"{protocol}://{self.host}"
        return base_url

    def _endpoint_url(self, endpoint_name):
        return f"{self.base_url}{self.ENDPOINTS_URLS[endpoint_name]}"

    def _auth_request_token(self):
        endpoint_url = self._endpoint_url(self.REQUEST_TOKEN)

        json_dict = {"api_key": self.api_key, "secret_key": self.secret_key}
        response = requests.post(
            url=endpoint_url,
            json=json_dict,
        )
        return json.loads(response.content)["access_token"]

    def _auth_refresh_token(self):
        endpoint_url = self._endpoint_url(self.REFRESH_TOKEN)

        json_dict = {
            "api_key": self.api_key,
            "secret_key": self.secret_key,
            "access_token": self.access_token,
        }
        response = requests.post(
            url=endpoint_url,
            json=json_dict,
        )
        self.access_token = json.loads(response.content)["access_token"]
        return self.access_token

    def _build_authorization_bearer(self):
        return {"Authorization": f"Bearer {self.access_token}"}

    @refresh_token_on_expiry
    def hello(self):
        endpoint_url = self._endpoint_url(self.HELLO)
        headers = self._build_authorization_bearer()
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "greeting": "hello",
        }
        response = requests.post(
            url=endpoint_url,
            headers=headers,
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def get_secret(self, secret_uuid):
        endpoint_url = self._endpoint_url(self.GET_SECRET)
        headers = self._build_authorization_bearer()
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {"uuid": secret_uuid},
        }

        response = requests.post(
            url=endpoint_url,
            headers=headers,
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def add_secret(self, secret_data):
        endpoint_url = self._endpoint_url(self.ADD_SECRET)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def accept_shared_secret(self, secret_data, tmp_master_key):
        endpoint_url = self._endpoint_url(self.ADD_SECRET)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "tmp_master_key": tmp_master_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def get_containers(self, container_name):
        endpoint_url = self._endpoint_url(self.GET_CONTAINERS)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": {
                "name": container_name
            },
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload
        )
        return response

    @refresh_token_on_expiry
    def add_container(self, name, description):
        endpoint_url = self._endpoint_url(self.ADD_CONTAINER)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": {
                "name": name,
                "description": description
            },
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def update_container(self, container_uuid, name, description):
        endpoint_url = self._endpoint_url(self.UPDATE_CONTAINER)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": {
                "uuid": container_uuid,
                "name": name,
                "description": description
            },
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def update_secret(self, **secret_data):
        endpoint_url = self._endpoint_url(self.UPDATE_SECRET)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {
                "uuid": secret_data.get("uuid"),
                "name": secret_data.get("name"),
                "containers": secret_data.get("containers"),
                "url": secret_data.get("url"),
                "value": secret_data.get("value"),
                "notes": secret_data.get("notes"),
                "identifiers": secret_data.get("identifiers"),
            },
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def get_secrets(self, secret_data):
        endpoint_url = self._endpoint_url(self.GET_SECRETS)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def duplicate_secret(self, secret_uuid):
        endpoint_url = self._endpoint_url(self.DUPLICATE_SECRET)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {
                "uuid": secret_uuid,
            },
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response

    @refresh_token_on_expiry
    def share_secret(self, secret_uuid, emails_list):
        endpoint_url = self._endpoint_url(self.SHARE_SECRET)

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {
                "uuid": secret_uuid,
            },
            "emails": emails_list,
        }
        response = requests.post(
            url=endpoint_url,
            headers=self._build_authorization_bearer(),
            json=payload,
        )
        return response
