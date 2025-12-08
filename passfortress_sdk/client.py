import json
from typing import Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .decorators import refresh_token_on_expiry


class ClientResponse:

    def __init__(self, status_code):
        self.status_code = status_code


class PassfortressClient:

    HELLO = "hello"
    REQUEST_TOKEN = "request_token"
    REFRESH_TOKEN = "refresh_token"
    GET_SECRETS = "get_secrets"
    GET_SECRET = "get_secret"
    ADD_SECRET = "add_secret"
    ACCEPT_SHARED_SECRET = "accept_shared_secret"
    UPDATE_SECRET = "update_secret"
    DUPLICATE_SECRET = "duplicate_secret"
    SHARE_SECRET = "share_secret"
    DELETE_SECRET = "delete_secret"
    GET_CONTAINERS = "get_containers"
    GET_CONTAINER = "get_container"
    ADD_CONTAINER = "add_container"
    UPDATE_CONTAINER = "update_container"
    DELETE_CONTAINER = "delete_container"
    GET_GROUPS = "get_groups"
    ADD_GROUP = "add_group"

    ENDPOINTS_URLS = {
        HELLO: "/api/hello/",
        REQUEST_TOKEN: "/api/auth/request-token/",
        REFRESH_TOKEN: "/api/auth/refresh-token/",
        GET_SECRETS: "/api/get-secrets/",
        GET_SECRET: "/api/get-secret/",
        ADD_SECRET: "/api/add-secret/",
        ACCEPT_SHARED_SECRET: "/api/accept-shared-secret/",
        UPDATE_SECRET: "/api/update-secret/",
        DUPLICATE_SECRET: "/api/duplicate-secret/",
        SHARE_SECRET: "/api/share-secret/",
        DELETE_SECRET: "/api/delete-secret/",
        GET_CONTAINERS: "/api/get-containers/",
        GET_CONTAINER: "/api/get-container/",
        ADD_CONTAINER: "/api/add-container/",
        UPDATE_CONTAINER: "/api/update-container/",
        DELETE_CONTAINER: "/api/delete-container/",
        GET_GROUPS: "/api/get-groups/",
        ADD_GROUP: "/api/add-group/",
    }

    DEFAULT_RETRIES_TOTAL = 2
    DEFAULT_RETRIES_CONNECT = 2
    DEFAULT_RETRIES_READ = 2
    DEFAULT_BACKOFF_FACTOR = 0.3
    DEFAULT_STATUS_FORCELIST = (429, 500, 502, 503, 504)
    DEFAULT_ALLOWED_METHODS = frozenset(["GET", "POST"])
    DEFAULT_POOL_CONNECTIONS = 10
    DEFAULT_POOL_MAXSIZE = 10
    DEFAULT_TIMEOUT: Tuple[float, float] = (2.0, 2.0)  # (connect, read)

    def __init__(
        self,
        api_key, 
            secret_key, 
            master_key, 
            host="app.passfortress.com",
            timeout: Optional[Tuple[float, float]] = None,
            retries_total: int = DEFAULT_RETRIES_TOTAL,
            retries_connect: int = DEFAULT_RETRIES_CONNECT,
            retries_read: int = DEFAULT_RETRIES_READ,
            backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
            pool_connections: int = DEFAULT_POOL_CONNECTIONS,
            pool_maxsize: int = DEFAULT_POOL_MAXSIZE,

    ):
        self.api_key = api_key
        self.secret_key = secret_key
        self.master_key = master_key
        self.host = host
        self.base_url = self._build_base_url()

        # Networking configuration
        self._timeout = timeout or self.DEFAULT_TIMEOUT
        self._session = self._create_session(
            retries_total=retries_total,
            retries_connect=retries_connect,
            retries_read=retries_read,
            backoff_factor=backoff_factor,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )

        self.access_token = self._auth_request_token()

    def _create_session(
            self,
            retries_total: int,
            retries_connect: int,
            retries_read: int,
            backoff_factor: float,
            pool_connections: int,
            pool_maxsize: int,
    ) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=retries_total,
            connect=retries_connect,
            read=retries_read,
            backoff_factor=backoff_factor,
            status_forcelist=self.DEFAULT_STATUS_FORCELIST,
            allowed_methods=self.DEFAULT_ALLOWED_METHODS,
            raise_on_status=False,  # do not raise automatically on status codes, we handle manually
        )
        adapter = HTTPAdapter(
            max_retries=retries,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        # Optionally set a common header to encourage keep-alive; requests already keeps alive by default.
        session.headers.update({"Connection": "keep-alive"})
        return session

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

        json_dict = {
            "api_key": self.api_key,
            "secret_key": self.secret_key
        }
        try:
            response = self._session.post(
                url=endpoint_url,
                json=json_dict,
                timeout=self._timeout,
            )
            response.raise_for_status()
            return response.json().get("access_token")
        except Exception as error:
            print(error)
            return None

    def _auth_refresh_token(self):
        endpoint_url = self._endpoint_url(self.REFRESH_TOKEN)

        json_dict = {
            "api_key": self.api_key,
            "secret_key": self.secret_key,
            "access_token": self.access_token
        }
        try:
            response = self._session.post(
                url=endpoint_url,
                json=json_dict,
                timeout=self._timeout,
            )
            response.raise_for_status()
            self.access_token = response.json().get("access_token")
            return self.access_token
        except Exception as error:
            print(error)
            return None

    def _build_authorization_bearer(self):
        return {"Authorization": f"Bearer {self.access_token}"}

    @refresh_token_on_expiry
    def _perform_request(self, endpoint_name, payload):

        # build URL
        endpoint_url = self._endpoint_url(endpoint_name)

        # get API response using a pooled, retried session with explicit timeouts
        try:
            api_response = self._session.post(
                url=endpoint_url,
                headers=self._build_authorization_bearer(),
                json=payload,
                timeout=self._timeout,
            )

            # build SDK response
            client_response = ClientResponse(status_code=api_response.status_code)

            try:
                response_dict = api_response.json()
                client_response.success = response_dict.pop("success", False)
                client_response.message = response_dict.pop("message", "")
                client_response.data = response_dict
            except ValueError as error:
                client_response.success = False
                client_response.message = error

            # return SDK response
            return client_response

        except requests.RequestException as error:
            # Network-level issue (timeout, connection error, etc.)
            client_response = ClientResponse(status_code=0)
            client_response.success = False
            client_response.message = str(error)
            client_response.data = {}
            return client_response

    def hello(self):

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "greeting": "hello",
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.HELLO,
            payload=payload
        )

        return sdk_response

    def get_secret(self, secret_uuid):
        """
        Retrieves a secret from the API using its UUID.

        Args:
            secret_uuid (str): The UUID of the secret to retrieve.

        Returns:
            requests.Response: The response object from the API containing the secret's
            details or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {"uuid": secret_uuid},
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.GET_SECRET,
            payload=payload
        )

        return sdk_response

    def add_secret(self, secret_data):
        """
        Adds a new secret to the API.

        Args:
            secret_data (dict): The secret data to be added. The dictionary contains the following keys:

                - secret_type (str): **Required**. One of ["password", "envfile"].
                - name (str): Optional. The name of the secret.
                - file_name (str): Optional. **Required if `secret_type == "file"`**. The name of encrypted file.
                - containers (list of dict): Optional. A list of containers to associate with the secret.
                    Each container dictionary must include:

                    - uuid (str): **Required**. The UUID of the container.

                - url (str): **Required if secret_type == "password"**. The URL associated with the password.
                - value (str): The value of the secret (e.g., password, .env file content, ...).
                - notes (str): Optional. Additional notes about the secret.
                - identifiers (list of dict): **Required if `secret_type == "password"`**. A list of key-value pairs to
                identify the secret.
                    Each identifier dictionary must include:

                    - key (str): **Required**. The identifier key.
                    - value (str): **Required**. The identifier value.

        Returns:
            requests.Response: The response object from the API containing the result of the
            operation, such as success confirmation or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.ADD_SECRET,
            payload=payload
        )

        return sdk_response

    def accept_shared_secret(self, secret_data, tmp_master_key):
        """
        Accepts a shared secret using a temporary master key.

        Args:
            secret_data (dict): The secret data containing the following key:

                - uuid (str): **Required**. The UUID of the shared secret.

            tmp_master_key (str): **Required**. A temporary master key used to decrypt the shared secret.

        Returns:
            requests.Response: The response object from the API containing the result of the operation,
            such as success confirmation or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "tmp_master_key": tmp_master_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.ACCEPT_SHARED_SECRET,
            payload=payload
        )

        return sdk_response

    def get_containers(self, container_data):
        """
        Retrieves a list of containers from the API.

        Args:
            container_data (dict): The container data used to filter the results, containing
            the following keys:

                - name (str): Optional. The name of the container to filter by.
                - description (str): Optional. The description (partial or total) of the container to filter by.

        Returns:
            requests.Response: The response object from the API containing the list of containers
            matching the provided filters or an error message if the request fails.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": container_data
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.GET_CONTAINERS,
            payload=payload
        )

        return sdk_response

    def get_container(self, container_uuid):
        """
        Retrieves a container from the API using its UUID.

        Args:
            container_uuid (str): The UUID of the container to retrieve.

        Returns:
            requests.Response: The response object from the API containing the container's
            details or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": {"uuid": container_uuid},
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.GET_CONTAINER,
            payload=payload
        )

        return sdk_response

    def add_container(self, container_data):
        """
        Add a new container to the API.

        Args:
            container_data (dict): The container data to create, containing the following keys:

                - name (str): **Required**. The name of the container.
                - description (str): Optional. A description of the container.

        Returns:
            requests.Response: The response object from the API containing the result of the
            update operation, such as success confirmation or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": container_data
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.ADD_CONTAINER,
            payload=payload
        )

        return sdk_response

    def update_container(self, container_data):
        """
        Updates an existing container in the API.

        Args:
            container_data (dict): The container data to update, containing the following keys:

                - uuid (str): **Required**. The UUID of the container to be updated.
                - name (str): **Required**. The name of the container.
                - description (str): Optional. A description of the container.

        Returns:
            requests.Response: The response object from the API containing the result of the
            update operation, such as success confirmation or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": container_data,
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.UPDATE_CONTAINER,
            payload=payload
        )

        return sdk_response

    def delete_container(self, container_uuid):
        """
        Delete a container from the API using its UUID.

        Args:
            container_uuid (str): The UUID of the container to be deleted.

        Returns:
            requests.Response: The response object from the API containing the status of operation.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "container": {"uuid": container_uuid},
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.DELETE_CONTAINER,
            payload=payload
        )

        return sdk_response

    def get_groups(self, group_data):
        """
        Retrieves a list of groups from the API.

        Args:
            group_data (dict): The group data used to filter the results, containing
            the following keys:

                - name (str): Optional. The name of the group to filter by.
                - description (str): Optional. The description (partial or total) of the group to filter by.

        Returns:
            requests.Response: The response object from the API containing the list of groups
            matching the provided filters or an error message if the request fails.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "group": group_data
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.GET_GROUPS,
            payload=payload
        )

        return sdk_response

    def add_group(self, group_data):
        """
        Add a new group to the API.

        Args:
            group_data (dict): The group data to create, containing the following keys:
                - parent_group (dict): Optional. A high level group, containing the following keys:
                    - uuid (str): **Required**. The UUID of the parent group.
                - name (str): **Required**. The name of the group.
                - description (str): Optional. A description of the group.
                - logo (dict): Optional. A base64 encoded logo image, containing the following keys:
                    - file_name(str): **Required**. The name of the logo image.
                    - content(str): **Required**. The image as a base64 encoded string.

        Returns:
            requests.Response: The response object from the API containing the result of the
            add operation, such as success confirmation or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "group": group_data
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.ADD_GROUP,
            payload=payload
        )

        return sdk_response

    def delete_secret(self, secret_uuid):
        """
        Delete a secret from the API using its UUID.

        Args:
            secret_uuid (str): The UUID of the secret to be deleted.

        Returns:
            requests.Response: The response object from the API containing the status of operation.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {"uuid": secret_uuid},
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.DELETE_SECRET,
            payload=payload
        )

        return sdk_response

    def update_secret(self, secret_data):
        """
        Updates an existing secret in the API.

        Args:
            secret_data (dict): The secret data to update, containing the following keys:

                - uuid (str): **Required**. The UUID of the secret to be updated.
                - secret_type (str): Optional. The type of the secret, either "password" or "envfile".
                - name (str): Optional. The name of the secret.
                - file_name (str): Optional. **Required if `secret_type == "file"`**. The name of encrypted file.
                - containers (list of dict): Optional. A list of containers to associate with the secret.
                    Each container dictionary must include:

                    - uuid (str): **Required**. The UUID of the container.

                - url (str): Optional. The URL associated with the secret, required only if `secret_type == "password"`.
                - value (str): **Required**. The decrypted value of the secret.
                - notes (str): Optional. Additional notes about the secret.
                - identifiers (list of dict): Optional. A list of key-value pairs to identify the secret,
                required only if `secret_type == "password"`.
                    Each identifier dictionary must include:

                    - key (str): **Required**. The identifier key.
                    - value (str): **Required**. The identifier value.

        Returns:
            requests.Response: The response object from the API containing the result of the
            update operation, such as success confirmation or an error message.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.UPDATE_SECRET,
            payload=payload
        )

        return sdk_response

    def get_secrets(self, secret_data):
        """
        Retrieves a list of secrets from the API based on the provided filters.

        Args:
            secret_data (dict): The secret data used to filter the results, containing
            the following keys:

                - secret_type (str): **Required**. The type of the secret, one of ["password", "envfile"].
                - name (str): Optional. The name of the secret to filter by.
                - file_name (str): Optional. **Required if `secret_type == "file"`**. The name of encrypted file.
                - url (str): Optional. The URL associated with the secret, relevant only if `secret_type == "password"`.
                - website (dict): Optional. Information about the website, relevant only if `secret_type == "password"`.
                Contains the following keys:
                    - uuid (str): Optional. The UUID of the website.
                    - hostname (str): Optional. The hostname of the website.
                    - login_url (str): Optional. The login URL for the website.
                    - automatic_password_change (bool): Optional. Whether the website supports automatic password change
                - containers (list of dict): Optional. A list of containers associated with the secret.
                Each container dictionary can include:
                    - uuid (str): Optional. The UUID of the container.
                    - name (str): Optional. The name of the container.
                    - description (str): Optional. The description of the container.
                - identifiers (list of dict): Optional. A list of identifiers, only if `secret_type == "password"`.
                Each identifier dictionary can include:
                    - uuid (str): Optional. The UUID of the identifier.
                    - key (str): Optional. The identifier key.
                    - value (str): Optional. The identifier value.
                - shared (bool): Optional. Whether to retrieve shared secrets. Defaults to `False`.

        Returns:
            requests.Response: The response object from the API containing the list of secrets
            matching the provided filters or an error message if the request fails.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": secret_data,
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.GET_SECRETS,
            payload=payload
        )

        return sdk_response

    def duplicate_secret(self, secret_uuid):
        """
        Duplicates an existing secret in the API.

        Args:
            secret_uuid (str): The UUID of the secret to duplicate.

        Returns:
            requests.Response: The response object from the API containing the duplicated secret
            details or an error message if the request fails.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {
                "uuid": secret_uuid,
            },
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.DUPLICATE_SECRET,
            payload=payload
        )

        return sdk_response

    def share_secret(self, secret_uuid, emails_list):
        """
        Share an existing secret in the API.

        Args:
            secret_uuid (str): The UUID of the secret to share.
            emails_list (list of str): The list of emails to share with.

        Returns:
            requests.Response: The response object from the API containing the shared secret
            details or an error message if the request fails.

        Raises:
            requests.RequestException: If the request to the API fails or encounters an error.
        """

        # payload definition
        payload = {
            "api_key": self.api_key,
            "master_key": self.master_key,
            "secret": {
                "uuid": secret_uuid,
            },
            "emails": emails_list,
        }

        # build SDK response
        sdk_response = self._perform_request(
            endpoint_name=self.SHARE_SECRET,
            payload=payload
        )

        return sdk_response

    def close(self) -> None:
        """
        Close the underlying HTTP session and free pooled connections.
        Call this when you're done with the client (e.g., at application shutdown).
        """
        try:
            self._session.close()
        except Exception:
            # Silently ignore close errors; session close is best-effort.
            pass
