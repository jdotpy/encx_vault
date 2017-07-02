from encxlib.security import RSA, SecurityError

import logging

class FingerprintMismatchError(SecurityError):
    pass

class MissingFingerprintError(SecurityError):
    pass

class FingerprintStore():
    def __init__(self, data={}):
        self.load_data(data)
        self._changed = False

    def load_data(self, data):
        if not data:
            data = {
                'users': {},
            }
        self.data = data

    def has_changed(self):
        return self._changed

    def export(self):
        return self.data

    def trust_user(self, user, fingerprint):
        self.data['users'][user] = fingerprint
        self._changed = True
        return True

    def untrust_user(self, user):
        self.data['users'].pop(user, None)
        self._changed = True
        return True

    def _valid_fingerprint(self, user, fingerprint):
        return self.data['users'].get(user, None) == fingerprint

    def _have_fingerprint(self, user):
        return user in self.data['users'] 

    def verify_user(self, user, fingerprint, allow_prompt=True):
        logging.debug('Validating fingerprint of {}'.format(user))

        # Check to see if its already in our store
        if self._have_fingerprint(user):
            if self._valid_fingerprint(user, fingerprint):
                return True
            else:
                raise FingerprintMismatchError('Fingerprint of user {} does not match records. The user either changed their key or their account was compromised.'.format(user))

        error = MissingFingerprintError('The user "{}" has not been trusted yet')
        if not allow_prompt:
            raise error

        print('\nServer has record of user "{}" having the following fingerprint:\n\n{}\n'.format(user, fingerprint))
        response = input('Does this fingerprint match the user\'s records? (yes/no)')
        if response in 'yes':
            self.trust_user(user, fingerprint)
            return True
        raise error
