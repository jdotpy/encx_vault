from .fingerprint_store import FingerprintStore
from encxlib import security

import requests

from getpass import getpass
import logging
import shutil
import json as JSON
import sys
import io


class VaultClient():
    version_numbers = (0, 2, 0)
    version = '.'.join([str(n) for n in version_numbers])

    def __init__(self,
                 host,
                 user,
                 private_key_path=None,
                 key_store_path=None,
                 token=None):
        self.host = host
        self.user = user
        self.private_key_path = private_key_path
        self.key_store_path = key_store_path
        self.session = requests.Session()

        if token:
            self.set_token(token, encrypted=False)

        if self.key_store_path:
            read_private_path(self.key_store_path)
        else:
            self.user_store = FingerprintStore({})

    def set_token(self, token, encrypted=False):
        if encrypted:
            self.token = self.private_key.decrypt(from_b64_str(token)).decode('utf-8')
        else:
            self.token = token
        self.session.headers = {
            'X-VAULT-USER': self.user,
            'X-VAULT-TOKEN': self.token,
        }

    def set_private_key(self, contents, passphrase=None):
        self._private_key = security.RSA(key=contents, passphrase=passphrase)

    @property
    def private_key(self):
        if not hasattr(self, '_private_key'):
            passphrase = getpass('Enter passphrase for key {}: '.format(self.private_key_path))
            try:
                self._private_key = security.load_rsa_key(self.private_key_path, passphrase=passphrase)
            except Exception as e:
                print('Could not load key at path:', self.private_key_path)
                raise e
        return self._private_key

    @property
    def public_key(self):
        if not hasattr(self, '_public_key'):
            self._public_key = security.RSA(self.private_key.get_public_key())
        return self._public_key

    def _request(self, method, path, json=True, **params):
        logging.debug('[{}] {}'.format(method, path))
        try:
            response = self.session.request(method, self.host + path, **params)
        except Exception as e:
            print('Error! Communication with server failed! {}'.format(str(e)))
            sys.exit(1)

        try:
            if json:
                data = response.json()
            else:
                data = response
        except ValueError as e:
            print('Error! Unable to parse response from server! {}'.format(str(e)))
            sys.exit(1)

        if str(response.status_code).startswith('4'):
            print('Your bad... {}'.format(data['message']))
            sys.exit(1)
        return data

    def ping(self):
        return self._request('GET', '/ping')

    def get_root_user(self, fingerprint=True):
        user_data = self._request('GET', '/user/root')['user']
        if fingerprint:
            user_data['fingerprint'] = security.RSA(key=user_data['public_key']).get_fingerprint()
        return user_data

    def get_user(self, user_name, fingerprint=False):
        user_data = self._request('GET', '/user', params={'user_name': user_name})['user']
        if fingerprint:
            user_data['fingerprint'] = security.RSA(key=user_data['public_key']).get_fingerprint()
        return user_data

    def add_user(self, user_name):
        return self._request('POST', '/users/new', data={'user_name': user_name})

    def init_user(self, public_key):
        return self._request('POST', '/user/init', data={'public_key': public_key})

    def audit_log(self, path=None, user=None, action=None):
        return self._request('GET', '/audit/log', params={
            'user': user,
            'path': path,
            'action': action,
        })

    def query(self, search=None):
        return self._request('GET', '/docs/query', params={'q': search})

    def doc_metadata(self, path, version=None, decrypt_key=False):
        metadata = self._request('GET', '/doc/meta', params={
            'path': path,
            'version': version,
        })
        if decrypt_key:
            encrypted_key = metadata['encrypted_key']
            key_bytes = self.private_key.decrypt(security.from_b64_str(encrypted_key))
            metadata['key'] = security.to_b64_str(key_bytes)
        return metadata

    def doc_data(self, path, version=None):
        return self._request('GET', '/doc/data', json=False, params={
            'path': path,
            'version': version,
        }).content

    def list_versions(self, path, extract=None):
        return self._request('GET', '/doc/versions', params={'path': path})

    def create_version(self, path, file_obj, update=False):
        document_bytes = file_obj.read()
        new_key = security.AES.generate_key()
        key_bytes = security.from_b64_str(new_key)
        aes = security.AES(key=new_key)
        encrypted_document_bytes, document_metadata = aes.encrypt(document_bytes)
        encrypted_key_bytes, key_metadata = self.public_key.encrypt(key_bytes)
        
        if update:
            upload_uri = '/doc/update'
        else:
            upload_uri = '/docs/new'
        add_response = self._request('POST', upload_uri,
            files={'encrypted_document': encrypted_document_bytes},
            data={
                'path': path,
                'encrypted_key': security.to_b64_str(encrypted_key_bytes),
                'document_metadata': JSON.dumps(document_metadata),
                'key_metadata': JSON.dumps(key_metadata),
                'document_fingerprint': hasher(document_bytes),
                'key_fingerprint': hasher(key_bytes),
            },
        )
        self._request('POST', '/doc/sanction', data={
            'path': path,
            'user': self.user,
            'encrypted_key': security.to_b64_str(encrypted_key_bytes),
            'key_metadata': JSON.dumps(key_metadata),
        })
        return add_response

    def sanction(self, path, user=None, force=False):
        user_data = self.get_user(user)
        if not self.user_store.can_trust_user(user, user_data['public_key']):
            raise SecurityError('SECURITY ERROR: Unable to validate public key of user {}'.format(user))

        doc_metadata = self.doc_metadata(path, decrypt_key=True)
        rsa = security.RSA(key=user_data['public_key'])
        encrypted_key_bytes, metadata = rsa.encrypt(from_b64_str(doc_metadata['key']))
        return self._request('POST', '/doc/sanction', data={
            'path': path,
            'user': user,
            'encrypted_key': to_b64_str(encrypted_key_bytes),
            'key_metadata': JSON.dumps(metadata),
        })

    def remove(self, path, version):
        return self._request('DELETE', '/doc/remove-version')

    def destroy(self, path):
        response = self._request('POST', '/doc/destroy', data={'path': path})
        return response
