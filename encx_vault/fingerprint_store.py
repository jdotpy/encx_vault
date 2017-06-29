from encxlib.security import RSA

import logging

class FingerprintStore():
    def __init__(self, client, data={}):
        self.client = client
        self.load_data(data)

    def load_data(self, data):
        if not data:
            data = {
                'root_user': None,
                'users': {},
            }
        self.data = data

    def export(self):
        return self.data

    def trust_user(self, user, fingerprint, root=False):
        self.data['users'][user] = fingerprint
        if root:
            self.data['root_user'] = user
        return True

    def _get_user_data(self, user):
        return self.client.get_user(user, fingerprint=True)

    def _valid_fingerprint(self, user, fingerprint):
        return self.data['users'].get(user, None) == fingerprint

    def _have_fingerprint(self, user):
        return user in self.data['users'] 

    def _verify_signature(self, signer_key, user_key, user_key_signature):
        rsa = RSA(key=signer_key)
        valid = rsa.verify(user_key, user_key_signature)
        return valid

    def can_trust_user(self, user, public_key):
        logging.debug('Validating public key of user {}'.format(user))
        fingerprint = RSA(key=public_key).get_fingerprint()

        # Check to see if its already in our store
        if self._valid_fingerprint(user, fingerprint):
            logging.debug('User {} can be trusted... already in our store.'.format(user))
            return True


        # Not in our store, we have to validate from a user that is
        # Step 1. build the the tree of users back to one we can trust
        user_chain = [self._get_user_data(user)]
        while True:
            current_user = user_chain[-1]
            signer = self._get_user_data(current_user['signer'])
            user_chain.append(signer)
            if self._valid_fingerprint(signer['user_name'], signer['fingerprint']):
                break
            if not signer['signer']:
                raise ValueError('SECURITY FAILURE: Unable to validate root user: ' + signer['user_name'])


        # Now that we have all the users check signatures from the top down
        signer = user_chain.pop()
        user_chain.reverse()
        for user_data in user_chain:
            is_valid = self._verify_signature(
                signer['public_key'],
                user_data['public_key'],
                user_data['signature']
            )
            if not is_valid:
                raise ValueError('SECURITY FAILURE: Signature doesnt validate for ' + user_data['user_name'])

        # All signatures passed, add trusts for these users
        for user_data in user_chain:
            has_existing = self._have_fingerprint(user_data['user_name'])
            self.trust_user(user_data['user_name'], user_data['fingerprint'])
            if has_existing:
                logging.warn('Updating trusted user {} with new fingerprint {} signed by {}.'.format(
                    user_data['user_name'],
                    user_data['fingerprint'],
                    user_data['signer'],
                ))
            else:
                logging.warn('Added new trusted user {} with fingerprint {} signed by {}.'.format(
                    user_data['user_name'],
                    user_data['fingerprint'],
                    user_data['signer'],
                ))

        # Give an 'ok
        return True
