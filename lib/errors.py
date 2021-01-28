import logging
from traceback import format_exc

log = logging.getLogger('credshed')

# by TheTechromancer

# General Credshed errors

class CredShedError(Exception):
    pass

class CredShedUtilError(CredShedError):
    pass

class CredShedValidationError(CredShedError):
    pass

class CredShedConfigError(CredShedError):
    pass

class CredShedMetadataError(CredShedError):
    pass

class CredShedDatabaseError(CredShedError):
    pass

class AlreadyInProgressError(CredShedDatabaseError):
    pass

class CredShedSourceError(CredShedError):
    pass

class AccountCreationError(CredShedError):
    pass

class LineAbsorptionError(AccountCreationError):
    pass

class CredShedEmailError(CredShedError):
    pass

# Parser-specific

class ParserError(CredShedError):
    pass

class TextParseError(ParserError):
    pass

class TextParsePermissionError(TextParseError):
    pass

class DelimiterError(TextParseError):
    pass

class FieldDetectionError(TextParseError):
    pass

class FileError(ParserError):
    pass

class FileReadError(FileError):
    pass

class FileHashError(FileError):
    pass

class FileSizeError(FileError):
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



def log_error(e, max_length=10000, exclude=()):
    '''
    Log a short version of the error
    If debugging is enabled, log the entire traceback
    excluded error types are only logged if debugging is enabled
    '''

    if log.level <= logging.DEBUG:
        log.error(format_exc()[:max_length])
    elif not type(e) in exclude:
        log.error(str(e)[:max_length] + ' (-v to debug)')