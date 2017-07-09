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
    default_vault_key_path = 'vault-key.pem'
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
            'parser': 'parse_init',
            'help': 'Initialize your client init',
        },
        'vault:me': {
            'run': 'cmd_me',
            'help': 'Show information about your user',
        },
        'vault:ping': {
            'run': 'cmd_ping',
            'help': 'Verify connection with vault',
        },
        'vault:add': {
            'run': 'cmd_add',
            'parser': 'parse_add',
            'help': 'Add target to vault at specified path',
        },
        'vault:add_user': {
            'run': 'cmd_add_user',
            'help': 'Add a user to the vault',
            'parser': 'parse_add_user',
        },
        'vault:edit': {
            'run': 'cmd_edit',
            'parser': 'parse_edit',
            'help': 'Edit a file in the vault',
        },
        'vault:remove_user': {
            'run': 'cmd_remove_user',
            'help': 'Remove a user from the vault',
            'parser': 'parse_remove_user',
        },
        'vault:trusted_users': {
            'run': 'cmd_trusted_users',
            'help': 'Show trusted users',
        },
        'vault:trust_user': {
            'run': 'cmd_trust_user',
            'parser': 'parse_trust_user',
            'help': 'Add a trusted user',
        },
        'vault:untrust_user': {
            'run': 'cmd_untrust_user',
            'parser': 'parse_untrust_user',
            'help': 'Remove a trusted user',
        },
        'vault:update': {
            'run': 'cmd_update',
            'parser': 'parse_update',
            'help': 'Create a new version of a document in the vault',
        },
        'vault:query': {
            'run': 'cmd_query',
            'parser': 'parse_query',
            'help': 'Query the vault for documents',
        },
        'vault:get': {
            'run': 'cmd_get',
            'parser': 'parse_get',
            'help': 'Download and decrypt a document from vault',
        },
        'vault:sanction': {
            'run': 'cmd_sanction',
            'parser': 'parse_sanction',
            'help': 'Grant another user access to a document',
        },
        'vault:history': {
            'run': 'cmd_history',
            'parser': 'parse_history',
            'help': 'Show the history of a particular document',
        },
        'vault:audit': {
            'run': 'cmd_audit',
            'parser': 'parse_audit',
            'help': 'Display the audit log',
        },
        'vault:destroy': {
            'run': 'cmd_destroy',
            'parser': 'parse_destroy',
            'help': 'Destroy version(s) of a document',
        },
    }

    #############################
    ## Internals

    @property
    def vault(self):
        """ Vault client loader """
        if not hasattr(self, '_vault'):
            vault_config = self.get_config()

            # cant create a client if we havent initialized vault
            if 'host' not in vault_config:
                logging.warning('Cant get client for vault as vault:init hasnt been run')
                self._vault = None
                return self._vault
            
            config_dir = self.client.get_config_dir()
            vault_key_file_path = os.path.join(config_dir, self.default_vault_key_path)
            key_store_path = os.path.join(config_dir, self.default_key_store_path)

            vault = VaultClient(
                host=vault_config['host'],
                user=vault_config['user'],
                private_key_path=vault_key_file_path,
                key_store_path=key_store_path,
            )
            vault.load_encrypted_token(
                vault_config['encrypted_token'],
                vault_config['encrypted_token_metadata'],
            )
            self._vault = vault

        return self._vault

    def _parse_path(self, path):
        """
            This allows all parsing to base paths on the 
            user's "home" directory on the vault
        """
        if not path:
            return path
        elif path.startswith('/'):
            return path
        else:
            return '/{}/{}'.format(self.vault.user, path)

    #############################
    ## File loader definitions 

    def _parse_vault_uri(self, uri):
        if not uri.startswith(self.vault_protocol):
            raise FileLoaderInvalidPath()

        _, path = uri[len(self.vault_protocol):]
        return path

    def vault_file_writer(self, path, data, overwrite=False):
        raise NotImplemented('This feature isnt implemented yet')

    def vault_file_loader(self, path):
        raise NotImplemented('This feature isnt implemented yet')


    #############################
    ## CLI Commands 

    def parse_init(self, parser):
        parser.add_argument('-s', '--server')
        parser.add_argument('-u', '--username')
        parser.add_argument('-n', '--name')

    def cmd_init(self, args):
        host = args.server or input('Enter url of vault server (e.g. https://vault.domain.com): ')
        username = args.username or input('Enter your assigned username: ')
        name = args.name or input('Pick a name for yourself: ')
        token = getpass('Enter user token received during account creation: ')
        key_password = getpass('Enter a password for your new vault key: ')

        logging.info('Generating Key')
        
        vault_client = VaultClient(host, username)
        vault_client.set_token(token)
        vault_client.set_private_key(security.RSA.generate_key())

        logging.info('Initializing your account....')
        initialize_response = vault_client.init_user(
            vault_client.rsa.get_public_key(),
            name=name,
        )
        if initialize_response['success']:
            logging.info('... done!')
        else:
            logging.error('... Failed to setup account!')
            logging.error('Error: ' + str(initialize_response['message']))
            return False

        # Update vault_client with new keys
        vault_client.set_token(initialize_response['token'])

        logging.info('Now, on to configuring the client.')
        vault_dir = os.path.expanduser(self.client.get_config_dir())

        logging.info('Creating new configuration files...')
        private_key_file_path = os.path.join(vault_dir, self.default_vault_key_path)
        key_store_path = os.path.join(vault_dir, self.default_key_store_path)

        encrypted_token, token_metadata = vault_client.get_encrypted_token()
        self.set_config({
            'host': vault_client.host,
            'user': vault_client.user,
            'encrypted_token': encrypted_token,
            'encrypted_token_metadata': token_metadata,
        })
        self.client.force_config_save()
        print('\tWriting key file...')
        security.write_private_path(
            private_key_file_path,
            vault_client.rsa.get_private_key(passphrase=key_password),
        )
        print('\t...done.')

        # Trust thy self
        vault_client.key_store_path = key_store_path
        vault_client.key_store.trust_user(
            username,
            vault_client.rsa.get_fingerprint(),
        )
        vault_client.write_key_store()


    def parse_add(self, parser):
        parser.add_argument('source', nargs=1, help='Plaintext data source')
        parser.add_argument('target', nargs=1, help='Path in vault to store entry')

    def cmd_add(self, args):
        data_source = args.source[0]
        target_path = self._parse_path(args.target[0])
        source_data = self.client.load_file(data_source)
        self.vault.create_version(target_path, source_data, update=False)

    def cmd_me(self, args):
        response = self.vault.ping()
        user_data = response['user']
        key_matches = user_data['public_key'] == self.vault.rsa.get_public_key()
        assert key_matches
        if not key_matches:
            logging.error('CRITICAL SECURITY ERROR: Your public key no longer matches the vaults references. Your account has been compromised! Tell others to vault:untrust ' + self.vault.user)
        print('Current User: {} ({})'.format(user_data['user_name'], user_data['name']))
        print('Administrator?', user_data['is_admin'])
        print('Key fingerprint:', self.vault.rsa.get_fingerprint())
        print('Client Version:', self.vault.version)

    def cmd_ping(self, args):
        response = self.vault.ping()
        print(response['message'])

    def parse_remove_user(self, parser):
        parser.add_argument('user', help='Username of user to delete', nargs='?')

    def cmd_remove_user(self, args):
        response = self.vault.remove_user(args.user)
        print('Removed user "{}".'.format(args.user))

    def parse_add_user(self, parser):
        parser.add_argument('user', help='Username for new user', nargs=1)

    def cmd_add_user(self, args):
        response = self.vault.add_user(args.user)
        print('Created user "{}".'.format(response['user_name']))
        print('User\'s new token:', response['token'])
        print('New user should run "crypt.py init" to start using crypt.')

    def parse_sanction(self, parser):
        parser.add_argument('document', help='Path of document to grant')
        parser.add_argument('user', help='Which user to grant access', nargs='?')

    def cmd_sanction(self, args):
        users = [args.user]

        for user in users:
            response = self.vault.sanction(args.document, user=user)
            print('Granting {} access to {} ...'.format(
                args.user, args.document,
            ), end='', flush=True)
            print('done!')

    def cmd_trusted_users(self, args):
        users = [
            {'username': user, 'fingerprint': fingerprint}
            for user, fingerprint in self.vault.key_store.data['users'].items()
        ]
        users.sort(key=lambda u: u['username'])
        print_table(users, fields=[
            ('username', 'Username'),
            ('fingerprint', 'Public Key Fingerprint'),
        ])

    def parse_trust_user(self, parser):
        parser.add_argument('-u', '--user', help='Which user to grant access', nargs='?')
        parser.add_argument('-f', '--fingerprint', help='Fingerprint to trust')

    def cmd_trust_user(self, args):
        user = args.user or input('Username of user: ')
        fingerprint = args.fingerprint or input('fingerprint of user\'s public key: ')
        self.vault.key_store.trust_user(user, fingerprint)

    def parse_untrust_user(self, parser):
        parser.add_argument('user', help='Which user to grant access', nargs='?')

    def cmd_untrust_user(self, args):
        user = args.user or input('Username of user: ')
        self.vault.key_store.untrust_user(user)

    def parse_destroy(self, parser):
        parser.add_argument('path', help='Path of document to destroy')

    def cmd_destroy(self, args):
        path = self._parse_path(args.path)
        response = self.vault.destroy(path)
        destroyed_docs = response['documents']
        print('Destroyed {} versions of document "{}"'.format(
            len(destroyed_docs),
            path,
        ))
        for doc in destroyed_docs:
            print(doc['id'])

    def parse_update(self, parser):
        parser.add_argument('-f', '--file', required=True)
        parser.add_argument('-p', '--path', required=True)

    def cmd_update(self, args):
        source_data = self.client.load_file(args.source[0])
        response = self.vault.create_version(args.target[0], source_data, update=True)
        print('New version created. ({})'.format(response['doc']['id']))

    def parse_query(self, parser):
        parser.add_argument('search_term', help='Text filter', nargs='?', default=None)

    def cmd_query(self, args):
        results = self.vault.query(args.search_term)
        if not results['documents']:
            print('No results found!')
            return False

        print_table(results['documents'], [
            ('path', 'Document'),
            ('creator', 'Author'),
            ('created', 'Last Modified'),
        ])

    def parse_audit(self, parser):
        parser.add_argument('-p', '--path', help='Document path')
        parser.add_argument('-u', '--user', help='user name')
        parser.add_argument('-a', '--action', help='action ("create", "read", "update", "delete")')

    def cmd_audit(self, args):
        action = args.action
        if action:
            action = action.lower()

        results = self.vault.audit_log(
            path=self._parse_path(args.path),
            user=args.user,
            action=args.action
        )
        entries = results['log']
        if not entries:
            print('No results found!')
            return False

        print_table(entries, [
            ('user_name', 'User'),
            ('action', 'Action'),
            ('document_path', 'Document'),
            ('document_version', 'Version'),
            ('timestamp', 'Timestamp'),
        ])

    def parse_get(self, parser):
        parser.add_argument('path', help='Path of document to read')
        parser.add_argument('-t', '--target', default='-', help='Target location to write data')
        parser.add_argument('-v', '--version', help='Version of document')

    def cmd_get(self, args):
        path = self._parse_path(args.path)
        document = self.vault.decrypt_document(path, args.version)
        self.client.write_file(args.target, document)

    def parse_edit(self, parser):
        parser.add_argument('path', help='Path of document to read')
        parser.add_argument('-v', '--version', help='Version of document')

    def cmd_edit(self, args):
        path = self._parse_path(args.path)
        payload = self.vault.decrypt_document(path, args.version)

        ext, validator = self.client.get_filetype_validator(None, path=path)
        success, new_data = self.client.edit_data(
            payload,
            extension=ext,
            validator=validator,
        )
        if not success:
            return success

        self.vault.create_version(path, new_data, update=True)
        return success

    def parse_history(self, parser):
        parser.add_argument('path', help='Path of document')

    def cmd_history(self, args):
        path = self._parse_path(args.path)
        response = self.vault.list_versions(path)
        print('Versions of document "{}"'.format(path))
        print_table(response['documents'], [
            ('creator', 'Creator'),
            ('created', 'Timestamp'),
            ('id', 'Version'),
        ])

    def cmd_remove(self, args):
        path = self._parse_path(args.path)
        response = self.vault.remove(path, args.version)
        print(response)

    ##########################
    ## Hooks

    def finish(self):
        if hasattr(self, '_vault') and self.vault.key_store.has_changed():
            self.vault.write_key_store()
