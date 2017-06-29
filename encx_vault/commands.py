from encxlib.commands import BasePlugin
from encxlib import security

from .client import VaultClient
from .utils import print_table

from getpass import getpass
import logging
import io
import os


class VaultCommands(BasePlugin):
    name = 'vault'
    vault_protocol = 'vault://'
    default_vault_key_path = 'private-key.pem'
    default_key_store_path = 'vault-key-store.json'

    file_loaders = {
        vault_protocol + '.*': {
            'loader': 'vault_file_loader',
            'writer': 'vault_file_writer',
        }   
    }

    commands = {
        'vault:init': {
            'run': 'cmd_init',
            'help': 'Initialize your client init',
        },
    }

    def _parse_vault_uri(self, uri):
        if not uri.startswith(self.vault_protocol):
            raise FileLoaderInvalidPath()

        _, path = uri[len(self.vault_protocol):]
        return path

    def cmd_init(self, args):
        host = input('Enter url of vault server (e.g. https://vault.domain.com): ')
        username = input('Enter user name: ')
        token = getpass('Enter user token received during account creation: ')
        key_password = getpass('Enter a password for your new vault key: ')

        logging.info('Generating Key')
        rsa = security.RSA(security.RSA.generate_key())
        private_key = rsa.get_private_key(passphrase=key_password)
        public_key = rsa.get_public_key()

        vault_client = VaultClient(host, username)
        vault_client.set_token(token, encrypted=False)
        vault_client.set_private_key(private_key, passphrase=key_password)

        logging.info('Initializing your account....')
        initialize_response = vault_client.init_user(public_key)
        if initialize_response['success']:
            logging.info('... done!')
        else:
            logging.error('... Failed to setup account!')
            logging.error('Error: ' + str(initialize_response['message']))
            return False

        # Update vault_client with new keys
        vault_client.set_token(initialize_response['token'], encrypted=False)

        logging.info('Now, on to configuring the client.')
        vault_dir = os.path.expanduser(self.client.get_config_dir())

        logging.info('Creating new configuration files...')
        private_key_file_path = os.path.join(vault_dir, self.default_vault_key_path)
        key_store_path = os.path.join(vault_dir, self.default_key_store_path)

        encrypted_token_bytes, token_metadata = vault_client.public_key.encrypt(
            vault_client.token.encode('utf-8')
        )
        self.set_config({
            'host': vault_client.host,
            'user': vault_client.user,
            'encrypted_token': security.to_b64_str(encrypted_token_bytes),
            'encrypted_token_metadata': token_metadata,
        })
        self.client.force_config_save()
        print('\tWriting key file...')
        security.write_private_path(private_key_file_path, private_key)
        print('\t...done.')
