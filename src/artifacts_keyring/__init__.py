# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from __future__ import absolute_import

__author__ = "Microsoft Corporation <python@microsoft.com>"
__version__ = "0.3.5"

import os
import warnings
from urllib.parse import urlparse

import keyring.backend
import keyring.credentials
import requests
from azure.identity import DefaultAzureCredential

ADO_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798"
USERNAME = "token"


class ArtifactsKeyringBackend(keyring.backend.KeyringBackend):
    SUPPORTED_NETLOC = (
        "pkgs.dev.azure.com",
        "pkgs.visualstudio.com",
        "pkgs.codedev.ms",
        "pkgs.vsts.me",
    )

    priority = 9.9

    def __init__(self):
        # In-memory cache of user-pass combination, to allow
        # fast handling of applications that insist on querying
        # username and password separately. get_password will
        # pop from this cache to avoid keeping the value
        # around for longer than necessary.
        self._cache = {}

    def get_credential(self, service, username):
        try:
            parsed = urlparse(service)
        except Exception as exc:
            warnings.warn(str(exc))
            return None

        netloc = parsed.netloc.rpartition("@")[-1]

        if netloc is None or not netloc.endswith(self.SUPPORTED_NETLOC):
            return None

        password = get_azure_token(service)
        if not username:
            username = USERNAME

        if username and password:
            self._cache[service, username] = password
            return keyring.credentials.SimpleCredential(username, password)

    def get_password(self, service, username):
        password = self._cache.get((service, username), None)
        if password is not None:
            return password

        creds = self.get_credential(service, None)
        if creds and username == creds.username:
            return creds.password

        return None

    def set_password(self, service, username, password):
        # Defer setting a password to the next backend
        raise NotImplementedError()

    def delete_password(self, service, username):
        # Defer deleting a password to the next backend
        raise NotImplementedError()


def _is_upload_endpoint(url):
    url = url[:-1] if url[-1] == "/" else url
    return url.endswith("pypi/upload")


def _no_auth_required(url):
    response = requests.get(url)
    return (
        response.status_code < 500
        and response.status_code != 401
        and response.status_code != 403
    )


def get_azure_token(url):
    # Public feed short circuit: return nothing if not getting credentials for the upload endpoint
    # (which always requires auth) and the endpoint is public (can authenticate without credentials).
    if not _is_upload_endpoint(url) and _no_auth_required(url):
        return None

    try:
        credential = DefaultAzureCredential().get_token(ADO_SCOPE)
        return credential.token
    except Exception as e:
        warnings.warn("Failed to retrieve Azure credential: {0}".format(e))
