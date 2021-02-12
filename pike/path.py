"""
pike.path - Path-like interface for working with a Tree object
"""

import io
from io import SEEK_CUR, SEEK_END, SEEK_SET
from pathlib import PureWindowsPath

from . import model
from . import ntstatus
from . import smb2


BYTES_PER_CREDIT = 64 * 1024


class PikeIO(io.RawIOBase):
    def __init__(self, path, handle, mode):
        self._channel = path._channel
        self._tree = path._tree
        self._offset = 0
        self._handle = handle
        self._mode = mode

    def close(self):
        self._handle.close()

    @property
    def closed(self):
        return self._handle.tree is None

    @property
    def end_of_file(self):
        return self._handle.create_response.end_of_file

    def seek(self, offset, whence=SEEK_SET):
        if whence == SEEK_SET:
            self._offset = offset
        elif whence == SEEK_CUR:
            self._offset += offset
        elif whence == SEEK_END:
            self._offset = self.end_of_file + offset
        return self._offset

    def seekable(self):
        return True

    def tell(self):
        return self._offset

    def truncate(self, size=None):
        raise NotImplementedError("truncate() not supported")

    def _read_range(self, start=0, end=None):
        offset = start
        if end is None:
            end = self.end_of_file
        response_buffers = []
        while offset < end:
            available = min(
                self._channel.connection.credits * BYTES_PER_CREDIT,
                self._channel.connection.negotiate_response.max_read_size,
            )
            try:
                read_resp = self._channel.read(self._handle, available, offset)
                response_buffers.append(read_resp)
                offset += len(read_resp)
            except model.ResponseError as re:
                if re.response.status == ntstatus.STATUS_END_OF_FILE:
                    return ""
                raise
        return b"".join(rb.tobytes() for rb in response_buffers)

    def readable(self):
        return "r" in self._mode.lower() or "+" in self._mode

    def readall(self):
        return self._read_range(self._offset)

    def readinto(self, b):
        read_resp = self._read_range(self._offset, len(b))
        bytes_read = len(read_resp)
        self._offset += bytes_read
        b[:bytes_read] = read_resp
        return bytes_read

    def _write_at(self, data, offset):
        n_data = len(data)
        bytes_written = 0
        while bytes_written < n_data:
            available = min(
                self._channel.connection.credits * BYTES_PER_CREDIT,
                self._channel.connection.negotiate_response.max_write_size,
            )
            chunk = data[offset + bytes_written : offset + bytes_written + available]
            count = self._channel.write(self._handle, offset + bytes_written, chunk)
            bytes_written += count
        return bytes_written

    def writable(self):
        return "w" in self._mode.lower() or "+" in self._mode

    def write(self, b):
        bytes_written = self._write_at(b, self._offset)
        self._offset += bytes_written
        return bytes_written


class PikePath(PureWindowsPath):
    def __new__(cls, channel, tree, *path_components):
        p = PureWindowsPath.__new__(PikePath, *path_components)
        p._channel = channel
        p._tree = tree
        return p

    def _from_parsed_parts(self, *args, **kwargs):
        """
        Override _from_parsed_parts to carry _channel and _tree when extending.

        This is a classmethod in the parent, but we'll override it as an
        instance method, because it's not called in the class context and we
        need to carry instance variables.
        """
        if not isinstance(self, PikePath):
            raise NotImplementedError(
                "Cannot extend from non-instance: {!r}".format(self)
            )
        new_path = super(PikePath, self)._from_parsed_parts(*args, **kwargs)
        # carry the channel and tree when joining paths
        new_path._channel = self._channel
        new_path._tree = self._tree
        return new_path

    @property
    def _path(self):
        return str(self).lstrip("\\")

    @classmethod
    def cwd(cls):
        raise NotImplementedError("No concept of cwd for {!r}".format(cls))

    @classmethod
    def home(cls):
        raise NotImplementedError("No concept of home for {!r}".format(cls))

    def stat(
        self,
        file_information_class=smb2.FILE_BASIC_INFORMATION,
        info_type=smb2.SMB2_0_INFO_FILE,
        options=0,
    ):
        with self._channel.create(
            self._tree,
            self._path,
            access=smb2.FILE_READ_ATTRIBUTES,
            disposition=smb2.FILE_OPEN,
            options=options,
        ).result() as handle:
            return self._channel.query_file_info(
                handle, file_information_class, info_type, first_result_only=True
            )

    def lstat(
        self,
        file_information_class=smb2.FILE_BASIC_INFORMATION,
        info_type=smb2.SMB2_0_INFO_FILE,
        options=0,
    ):
        options = options | smb2.FILE_OPEN_REPARSE_POINT
        return self.stat(
            file_information_class=file_information_class,
            info_type=info_type,
            options=options,
        )

    def chmod(self, mode):
        raise NotImplementedError("ACL modification is not supported")

    lchmod = chmod

    def exists(self, options=0):
        try:
            with self._channel.create(
                self._tree,
                self._path,
                access=0,
                disposition=smb2.FILE_OPEN,
                options=options,
            ).result() as handle:
                return True
        except model.ResponseError as re:
            if re.response.status not in (
                ntstatus.STATUS_OBJECT_NAME_NOT_FOUND,
                ntstatus.STATUS_OBJECT_PATH_NOT_FOUND,
            ):
                raise
        return False

    def expanduser(self):
        raise NotImplementedError("expanduser() is not supported")

    def glob(self, pattern):
        raise NotImplementedError("glob() is not supported")

    def group(self):
        raise NotImplementedError("group() is not supported")

    def is_dir(self):
        return self.exists(options=smb2.FILE_DIRECTORY_FILE)

    def is_file(self):
        return self.exists(options=smb2.FILE_NON_DIRECTORY_FILE)

    def is_symlink(self):
        return self.exists(options=smb2.FILE_OPEN_REPARSE_POINT)

    def is_mount(self):
        return True  # all paths are on SMB mount

    def is_socket(self):
        return False

    def is_fifo(self):
        return False  # might be supported some day

    def is_block_device(self):
        return False

    def is_char_device(self):
        return False

    def iterdir(self):
        with self._channel.create(
            self._tree,
            self._path,
            access=smb2.GENERIC_READ,
            disposition=smb2.FILE_OPEN,
            options=smb2.FILE_DIRECTORY_FILE,
        ).result() as handle:
            for item in self._channel.enum_directory(
                handle, file_information_class=smb2.FILE_NAMES_INFORMATION
            ):
                if item.file_name in (".", ".."):
                    continue
                yield self / item.file_name

    def mkdir(self, mode=None, parents=False, exist_ok=False):
        if mode is not None:
            warnings.warn("`mode` argument is not handled at this time", stacklevel=2)
        try:
            with self._channel.create(
                self._tree,
                self._path,
                access=smb2.GENERIC_WRITE,
                disposition=smb2.FILE_CREATE,
                options=smb2.FILE_DIRECTORY_FILE,
            ).result() as handle:
                return
        except model.ResponseError as re:
            if re.response.status == ntstatus.STATUS_OBJECT_NAME_COLLISION and exist_ok:
                return
            if not parents or self.parent == self:
                raise
            self.parent.mkdir(parents=True, exist_ok=True)
            self.mkdir(mode, parents=False, exist_ok=exist_ok)

    def open(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        """
        Open a file-like with immediate IO via pike
        """
        buffer_class = io.BufferedReader
        access = 0
        disposition = smb2.FILE_OPEN
        mode = mode.lower()
        if "r" in mode or "+" in mode:
            access |= smb2.GENERIC_READ
        if "a" in mode or "w" in mode or "+" in mode:
            access |= smb2.GENERIC_WRITE
            buffer_class = io.BufferedWriter
        if "+" in mode:
            buffer_class = io.BufferedRandom
        if "x" in mode:
            disposition = smb2.FILE_CREATE
        elif "a" in mode:
            disposition = smb2.FILE_OPEN_IF
        elif "w" in mode or "+" in mode:
            disposition = smb2.FILE_SUPERSEDE
        handle = self._channel.create(
            self._tree,
            self._path,
            access=access,
            disposition=disposition,
            options=smb2.FILE_NON_DIRECTORY_FILE,
        ).result()
        raw_io = PikeIO(self, handle, mode)
        if "a" in mode:
            raw_io.seek(0, SEEK_END)
        if "b" in mode and buffering == 0:
            return raw_io
        if buffering == -1:
            buffer_size = BYTES_PER_CREDIT
        buffered_io = buffer_class(raw_io, buffer_size=buffer_size)
        if "b" in mode:
            return buffered_io
        return io.TextIOWrapper(
            buffered_io, encoding=encoding, errors=errors, newline=newline
        )

    def read_bytes(self):
        """
        Return the binary contents of the pointed-to file as a bytes object.
        """
        with self.open("rb") as f:
            return f.read()

    def read_text(self, encoding=None, errors=None):
        """
        Return the decoded contents of the pointed-to file as a string.
        """
        with self.open("r") as f:
            return f.read()

    def rmdir(self, missing_ok=False):
        self.unlink(missing_ok=missing_ok, options=smb2.FILE_DIRECTORY_FILE)

    def unlink(self, missing_ok=False, options=smb2.FILE_NON_DIRECTORY_FILE):
        try:
            with self._channel.create(
                self._tree,
                self._path,
                access=smb2.DELETE,
                disposition=smb2.FILE_OPEN,
                options=options | smb2.FILE_DELETE_ON_CLOSE,
            ).result() as handle:
                pass
        except model.ResponseError as re:
            if (
                re.response.status
                in (
                    ntstatus.STATUS_OBJECT_NAME_NOT_FOUND,
                    ntstatus.STATUS_OBJECT_PATH_NOT_FOUND,
                )
                and missing_ok
            ):
                return
            elif re.response.status == ntstatus.STATUS_STOPPED_ON_SYMLINK:
                return self.unlink(
                    missing_ok=missing_ok,
                    options=options | smb2.FILE_OPEN_REPARSE_POINT,
                )
            raise

    def write_bytes(self, data):
        """
        Open the file pointed to in bytes mode, write data to it, and close the file.
        """
        with self.open("wb") as f:
            return f.write(data)

    def write_text(self, data, encoding=None, errors=None):
        """
        Open the file pointed to in text mode, write data to it, and close the file
        """
        with self.open("w") as f:
            return f.write(data)
