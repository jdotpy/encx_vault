from .fingerprint_store import FingerprintStore
from encxlib import security
from encxlib import schemes

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
        self.set_token(token)
        self.load_key_store()

    def load_key_store(self):
        if self.key_store_path:
            try:
                store_data = security.read_private_path(self.key_store_path)
            except FileNotFoundError:
                self.key_store = FingerprintStore({})
                return self.key_store

            self.key_store = FingerprintStore(JSON.loads(store_data))
            return self.key_store

        self.key_store = FingerprintStore({})
        return self.key_store

    def write_key_store(self):
        if not self.key_store_path:
            logging.warn('Unable to save key store changes. Missing key store path!')
        security.write_private_path(
            self.key_store_path,
            JSON.dumps(self.key_store.export()),
        )

    def set_token(self, token):
        self.token = token
        self.session.headers = {
            'X-VAULT-USER': self.user,
            'X-VAULT-TOKEN': self.token or '',
        }

    def load_encrypted_token(self, encrypted_token, metadata):
        token = self.rsa.decrypt(security.from_b64_str(encrypted_token)).decode('utf-8')
        self.set_token(token)

    def get_encrypted_token(self):
        encrypted_token_bytes, meta = self.rsa.encrypt(self.token.encode('utf-8'))
        encrypted_token = security.to_b64_str(encrypted_token_bytes)
        return encrypted_token, meta

    def set_private_key(self, contents, passphrase=None):
        self._rsa = security.RSA(contents, passphrase=passphrase)

    @property
    def rsa(self):
        if not hasattr(self, '_rsa'):
            self._rsa = security.RSA(security.load_rsa_key(self.private_key_path))
        return self._rsa

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

    def get_user(self, user_name, fingerprint=False):
        user_data = self._request('GET', '/user/{}'.format(user_name))['user']
        if fingerprint:
            rsa = security.RSA(key=user_data['public_key'])
            user_data['fingerprint'] = rsa.get_fingerprint()
        return user_data

    def add_user(self, user_name):
        return self._request('POST', '/users/new', data={'user_name': user_name})

    def remove_user(self, user_name):
        return self._request('DELETE', '/user/{}'.format(user_name))

    def init_user(self, public_key, name=None):
        return self._request('POST', '/users/init', data={
            'public_key': public_key,
            'name': name,
        })

    def audit_log(self, path=None, user=None, action=None):
        return self._request('GET', '/audit/log', params={
            'user': user,
            'path': path,
            'action': action,
        })

    def query(self, search=None):
        return self._request('GET', '/docs/query', params={'q': search})

    def doc_metadata(self, path, version=None):
        metadata = self._request('GET', '/doc/meta', params={
            'path': path,
            'version': version,
        })
        return metadata

    def doc_data(self, path, version=None):
        raw_data = self._request('GET', '/doc/data', json=False, params={
            'path': path,
            'version': version,
        }).content
        return raw_data

    def decrypt_document_key(self, path, version=None):
        meta = self.doc_metadata(path, version=version)
        encrypted_key = meta['encrypted_key']
        key_bytes = self.rsa.decrypt(security.from_b64_str(encrypted_key))
        return security.to_b64_str(key_bytes)

    def decrypt_document(self, path, version=None, verify=True):
        meta = self.doc_metadata(path, version=version)
        encrypted_document = self.doc_data(path, version=version)

        scheme = schemes.RSAScheme(self.rsa.get_private_key())
        document = scheme.decrypt(encrypted_document, {
            'rsa': meta['key_metadata'],
            'aes': meta['document_metadata'],
            'encrypted_key': meta['encrypted_key'],
        })

        # Verify Signature
        if verify:
            signature = meta.get('signature')
            user = self.get_verified_user(meta['creator'])
            signer = security.RSA(user['public_key'])
            if not signer.verify(document, signature):
                raise SecurityError('Data does not match fingerprint! The source data cannot be trusted.')
        return document

    def list_versions(self, path, extract=None):
        return self._request('GET', '/doc/versions', params={'path': path})

    def create_version(self, path, data, update=False):
        document_bytes = data
        document_signature = self.rsa.sign(data)

        scheme = schemes.RSAScheme(self.rsa.get_private_key())
        ciphertext, meta, aes_key = scheme.encrypt(document_bytes, include_aes_key=True)

        encrypted_key = meta['encrypted_key']
        key_metadata = meta['rsa']
        document_metadata = meta['aes']
        
        if update:
            upload_uri = '/doc/update'
        else:
            upload_uri = '/docs/new'
        add_response = self._request('POST', upload_uri,
            files={'encrypted_document': ciphertext},
            data={
                'path': path,
                'document_metadata': JSON.dumps(document_metadata),
                'signature': document_signature,
            },
        )
        self._request('POST', '/doc/sanction', data={
            'path': path,
            'user': self.user,
            'encrypted_key': encrypted_key,
            'key_metadata': JSON.dumps(key_metadata),
        })
        return add_response

    def verify_user(self, user_obj):
        fingerprint = security.RSA(user_obj['public_key']).get_fingerprint()
        self.key_store.verify_user(user_obj['user_name'], fingerprint)

    def get_verified_user(self, user_name):
        user_data = self.get_user(user_name)
        self.verify_user(user_data)
        return user_data

    def sanction(self, path, version=None, user=None, force=False):
        key = self.decrypt_document_key(path, version=version)

        user_data = self.get_verified_user(user)
        rsa = security.RSA(key=user_data['public_key'])
        key_bytes = security.from_b64_str(key)
        encrypted_key_bytes, metadata = rsa.encrypt(key_bytes)

        return self._request('POST', '/doc/sanction', data={
            'path': path,
            'user': user,
            'encrypted_key': security.to_b64_str(encrypted_key_bytes),
            'key_metadata': JSON.dumps(metadata),
        })

    def remove(self, path, version):
        return self._request('DELETE', '/doc/remove-version')

    def destroy(self, path):
        response = self._request('POST', '/doc/destroy', data={'path': path})
        return response
