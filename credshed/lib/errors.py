#!/usr/bin/env python3

# by TheTechromancer

# General Credshed errors

class CredShedError(Exception):
    pass

class CredShedUtilError(CredShedError):
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

# TextParse-specific

class TextParseError(CredShedError):
    pass

class TextParsePermissionError(TextParseError):
    pass

class DelimiterError(TextParseError):
    pass

class FieldDetectionError(TextParseError):
    pass


# Filestore-specific

class FilestoreError(CredShedError):
    pass

class FilestoreHashError(FilestoreError):
    pass

class FilestoreOrphanError(FilestoreError):
    pass

class FilestoreMetadataError(FilestoreError):
    pass

class FilestoreUtilError(CredShedUtilError):
    pass