#!/usr/bin/env python3.7

# by TheTechromancer


class CredShedError(Exception):
    pass

class CredShedTimeout(CredShedError):
    pass

class CredShedDatabaseError(CredShedError):
    pass

class AccountCreationError(CredShedError):
    pass