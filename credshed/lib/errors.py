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

class LineAbsorptionError(AccountCreationError):
    pass

# QuickParse-specific

class QuickParseError(CredShedError):
    pass

class QuickParsePermissionError(QuickParseError):
    pass

class DelimiterError(QuickParseError):
    pass

class FieldDetectionError(QuickParseError):
    pass