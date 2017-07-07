__all__ = [
        'auth',
        'core',
        'crypto',
        'digest',
        'kerberos',
        'model',
        'netbios',
        'ntlm'
        'nttime',
        'ntstatus',
        'smb2',
        'test',
        'transport',
]
__version_info__ = (0, 2, 11)
__version__ = "{0}.{1}.{2}".format(*__version_info__)

default_timeout = 30


class TimeoutError(Exception):
    """A timeout was encountered during async processing"""
    pass


class StateError(Exception):
    """Internal state is inconsistent for the given operation"""
    pass
