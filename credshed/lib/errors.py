#!/usr/bin/env python3.7

# by TheTechromancer


class CredShedError(Exception):
    pass

class CredShedConfigError(CredShedError):
    pass

class CredShedMetadataError(CredShedError):
    pass

class CredShedTimeoutError(CredShedError):
    pass

class CredShedDatabaseError(CredShedError):
    pass

class AccountCreationError(CredShedError):
    pass