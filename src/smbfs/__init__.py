# -*- coding: utf-8 -*-
import os
import stat
import errno
import datetime
import threading

import smbc
import fs
from fs.base import FS as BaseFS, DummyLock, synchronize
from fs.errors import (FSClosedError, NoPathURLError, ResourceNotFoundError,
                       ResourceInvalidError, DestinationExistsError, ParentDirectoryMissingError,
                       DirectoryNotEmptyError, FSError, RemoteConnectionError,
                       PermissionDeniedError, StorageSpaceError)
from fs.path import normpath, abspath, recursepath, dirname, basename


__all__ = ['SMBFS']


class SMBFS(BaseFS):

    _meta = {'thread_safe': True,
             'virtual': False,
             'read_only': False,
             'unicode_paths': True,
             # windows smb share is case insensitive but unix share isn't so
             'case_insensitive_paths': False,
             'network': True,
             'atomic.move': True,
             'atomic.makedir': True,
             'atomic.rename': True,
             'atomic.setcontents': False}

    CHECK_IS_EXISTS = 0
    CHECK_IS_FILE = 1
    CHECK_IS_DIR = 2

    def __init__(self, host, share, username=None, password=None, workgroup=None, thread_synchronize=True):
        self._host = host
        self._share = share
        self._username = username
        self._password = password
        self._workgroup = workgroup

        self._uri = ''.join(['smb://', self._from_unicode(self._host), '/', self._from_unicode(self._share)])
        self._closed = False

        super(SMBFS, self).__init__(thread_synchronize=thread_synchronize)

    def __str__(self):
        args = (self.__class__.__name__, self._uri, self._username)
        return '<%s: %s:%s>' % args

    __repr__ = __str__

    def __getstate__(self):
        state = super(SMBFS, self).__getstate__()
        if '_conn_res' in state:
            del state['_conn_res']
        del state['_lock']
        return state

    def __setstate__(self, state):
        super(SMBFS, self).__setstate__(state)
        self._lock = threading.RLock() if self.thread_synchronize else DummyLock()

    @property
    def conn(self):
        try:
            self._lock.acquire()
            if not self._closed:
                if not hasattr(self, '_conn_res'):
                    auth_fnc = lambda se, sh, w, u, p: (self._workgroup if self._workgroup is not None else w,
                                                        self._username if self._username is not None else u,
                                                        self._password if self._password is not None else p)

                    self._conn_res = _SMBConnector(auth_fnc)
                return self._conn_res
            else:
                raise FSClosedError('Create connection to the remote host')
        finally:
            self._lock.release()

    def _from_unicode(self, st):
        return st.encode('utf-8') if isinstance(st, unicode) else st

    def _to_unicode(self, st):
        return st if isinstance(st, unicode) else unicode(st, 'utf-8')

    def _prepare_normpath(self, path):
        return normpath(self._to_unicode(path))

    def _prepare_abspath(self, path):
        return abspath(self._prepare_normpath(path))

    def smb_path(self, path='/'):
        if not isinstance(path, basestring):
            raise Exception('Invalid path')

        if not len(path):
            path = '/'

        path = self._from_unicode(path)

        if path[0] != '/':
            return ''.join([self._uri, '/', path])
        else:
            return ''.join([self._uri, path])

    @synchronize
    def _check_fs_node(self, path, mode=None):
        try:
            path = normpath(path)
            if path in ('', '/'):
                return True if mode in (self.CHECK_IS_DIR, self.CHECK_IS_EXISTS) else False

            st = self.conn.stat(self.smb_path(path))
            md = st[stat.ST_MODE]

            if mode == self.CHECK_IS_EXISTS:
                return True
            elif mode == self.CHECK_IS_DIR:
                return stat.S_ISDIR(md)
            elif mode == self.CHECK_IS_FILE:
                return stat.S_ISREG(md)

        except smbc.NoEntryError:
            pass

        return False

    @synchronize
    def _readdir(self, path):
        path = normpath(path)
        res = self.conn.opendir(self.smb_path(path)).getdents()
        return [self._to_unicode(x.name) for x in res[2:]]

    @synchronize
    def createfile(self, path, wipe=False):
        path = normpath(path)
        if not wipe and self.isfile(path):
            return
        self.conn.creat(self.smb_path(path))

    @synchronize
    def desc(self, path):
        if not self.exists(path):
            return ''
        return self.smb_path(path)

    def getpathurl(self, path, allow_none=False):
        if self.exists(path):
            return self.smb_path(path)
        elif allow_none:
            return None
        else:
            raise NoPathURLError(path=path)

    @synchronize
    def close(self):
        if not self._closed:
            try:
                del self._conn_res
            except AttributeError:
                pass
            self._closed = True

    def exists(self, path):
        return self._check_fs_node(path, mode=self.CHECK_IS_EXISTS)

    def isdir(self, path):
        return self._check_fs_node(path, mode=self.CHECK_IS_DIR)

    def isfile(self, path):
        return self._check_fs_node(path, mode=self.CHECK_IS_FILE)

    @synchronize
    def getsize(self, path):
        try:
            path = normpath(path)
            st = self.conn.stat(self.smb_path(path))
            return st[stat.ST_SIZE]
        except smbc.NoEntryError:
            raise ResourceNotFoundError(path)

    @synchronize
    def open(self, path, mode="r", **kwargs):
        path = normpath(path)
        mode = mode.lower()

        if self.isdir(path):
            raise ResourceInvalidError(path)

        return _SMBFile(self, path, mode)

    @synchronize
    def copy(self, src, dst, overwrite=False, chunk_size=1024 * 1024):
        src = normpath(src)

        if not self.isfile(src):
            if self.isdir(src):
                raise ResourceInvalidError(src, msg="Source is not a file: %(path)s")
            raise ResourceNotFoundError(src)

        dst = normpath(dst)

        if not overwrite and self.exists(dst):
            raise DestinationExistsError(dst)

        src_file = None
        dst_file = None

        try:
            src_file = self.open(src, 'r')
            dst_file = self.open(dst, 'w')

            while 1:
                copy_buffer = src_file.read(chunk_size)
                if copy_buffer:
                    dst_file.write(copy_buffer)
                else:
                    break
        finally:
            if src_file is not None:
                src_file.close()
            if dst_file is not None:
                dst_file.close()

    @synchronize
    def listdir(self, path="./", wildcard=None, full=False, absolute=False, dirs_only=False, files_only=False):
        path = normpath(path)

        if not self.exists(path):
            raise ResourceNotFoundError(path)
        if not self.isdir(path):
            raise ResourceInvalidError(path)

        paths = self._readdir(path)
        path = self._to_unicode(path)

        return self._listdir_helper(path, paths, wildcard, full, absolute, dirs_only, files_only)

    @synchronize
    def makedir(self, path, recursive=False, allow_recreate=False):
        path = normpath(path)
        if path in ('', '/'):
            return

        if recursive:
            created = False
            for path_part in recursepath(path):
                if not self.isdir(path_part):
                    self.conn.mkdir(self.smb_path(path_part))
                    created = True
                else:
                    if self.isfile(path_part):
                        raise ResourceInvalidError(path_part)

            if not created and not allow_recreate:
                raise DestinationExistsError(path)
        else:
            base = dirname(path)
            if not self.exists(base):
                raise ParentDirectoryMissingError(path)

            if not allow_recreate:
                if self.exists(path):
                    if self.isfile(path):
                        raise ResourceInvalidError(path)
                    raise DestinationExistsError(path)
                self.conn.mkdir(self.smb_path(path))
            else:
                if not self.isdir(path):
                    self.conn.mkdir(self.smb_path(path))

    @synchronize
    def move(self, src, dst, overwrite=False, chunk_size=16384):
        if self.isfile(src):
            src = self._prepare_normpath(src)
            dst = self._prepare_normpath(dst)

            if self.isdir(dst):
                dst = '/'.join([dst, basename(src)])
            if not overwrite and self.exists(dst):
                raise DestinationExistsError(dst)

            self.rename(src, dst)
        else:
            raise ResourceInvalidError(src, msg="Source is not a file: %(path)s")

    @synchronize
    def remove(self, path):
        if not self.exists(path):
            raise ResourceNotFoundError(path)
        if not self.isfile(path):
            raise ResourceInvalidError(path)

        self.conn.unlink(self.smb_path(path))

    @synchronize
    def removedir(self, path, recursive=False, force=False):
        path = self._prepare_abspath(path)

        if not self.exists(path):
            raise ResourceNotFoundError(path)
        if self.isfile(path):
            raise ResourceInvalidError(path)

        lst = self.listdir(path, full=True)

        if len(lst) > 0:
            if not force:
                raise DirectoryNotEmptyError(path)
            else:
                for rpath in lst:
                    try:
                        if self.isfile(rpath):
                            self.remove(rpath)
                        elif self.isdir(rpath):
                            self.removedir(rpath, force=force)
                    except FSError:
                        pass

        self.conn.rmdir(self.smb_path(path))

        if recursive:
            try:
                self.removedir(dirname(path), recursive=True)
            except DirectoryNotEmptyError:
                pass

    @synchronize
    def rename(self, src, dst):
        src_path = self._prepare_abspath(src)
        dst_path = self._prepare_abspath(dst)

        if not self.exists(src):
            raise ResourceNotFoundError(src)

        # src and dst pathes should be different
        if src_path == dst_path:
            raise ResourceInvalidError(dst)

        src_is_dir = self.isdir(src)

        if self.exists(dst):
            dst_is_dir = self.isdir(dst)

            if (src_is_dir and not dst_is_dir)\
                or (dst_is_dir and not src_is_dir)\
                    or (src_is_dir and dst_is_dir and src_path.lower() != dst_path.lower()):
                # note about last condition: in reality unix system allow us
                # to rename src directory to dst directory only in case dst directory is empty
                # but for simplicity we don't consider this case
                raise ResourceInvalidError(dst)

        elif not self.exists(dirname(dst)):
            raise ParentDirectoryMissingError(dst)
        else:
            dst_is_dir = src_is_dir

        # check that src isn't a parent of dst
        if src_is_dir and dst_is_dir:
            src_path = ''.join([src_path, '/'])
            dst_path = ''.join([dst_path, '/'])
            if dst_path.startswith(src_path, 0):
                raise ResourceInvalidError(dst)

        try:
            self.conn.rename(self.smb_path(src_path), self.smb_path(dst_path))
        except:
            raise ResourceInvalidError(dst)

    @synchronize
    def getinfo(self, path):
        try:
            path = normpath(path)
            st = self.conn.stat(self.smb_path(path))

            return {
                'st_mode': st[stat.ST_MODE],
                'size': st[stat.ST_SIZE],
                'accessed_time': datetime.datetime.fromtimestamp(st[stat.ST_ATIME]) if st[stat.ST_ATIME] else None,
                'modified_time': datetime.datetime.fromtimestamp(st[stat.ST_MTIME]) if st[stat.ST_MTIME] else None,
                'created_time': datetime.datetime.fromtimestamp(st[stat.ST_CTIME]) if st[stat.ST_CTIME] else None
            }
        except smbc.NoEntryError:
            raise ResourceNotFoundError(path)


class _SMBConnector(object):

    def __init__(self, smb_auth_fnc):
        self._ctx = smbc.Context(auth_fn=smb_auth_fnc, debug=0)
        self._ctx.optionDebugToStderr = False

    def __getattr__(self, name):
        def _runMethod(*args, **kwargs):
            def prepare_error(exp):
                return ''.join(['run command "', name, '", args: ',
                                str(args), ', kwargs: ', str(kwargs), ', smbc exception: ', str(exp)])

            try:
                method = getattr(self._ctx, name)
                return method(*args, **kwargs)
            except smbc.TimedOutError, e:
                raise RemoteConnectionError(prepare_error(e), details=e)
            except smbc.PermissionError, e:
                raise PermissionDeniedError(prepare_error(e), details=e)
            except smbc.NoSpaceError, e:
                raise StorageSpaceError(prepare_error(e), details=e)
            except RuntimeError as e:
                if int(e[0]) == errno.EROFS:
                    raise PermissionDeniedError(prepare_error(e), details=e)
                raise

        return _runMethod


class _SMBFile(object):

    """ A file-like that provides access to a file being streamed over smb."""

    blocksize = 1024 * 64

    def __init__(self, smbfs, path, mode):
        self.smbfs = smbfs
        self.path = normpath(path)
        self.mode = mode
        self.file = None
        if not hasattr(self, '_lock'):
            self._lock = threading.RLock() if smbfs.thread_synchronize else DummyLock()
        self._open()

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    @synchronize
    def _open(self):
        self.pos = 0
        self.file_size = None
        self.closed = False
        self.smb_uri_path = self.smbfs.smb_path(self.path)

        open_mode = None

        if 'r' in self.mode and '+' in self.mode:
            open_mode = os.O_RDWR
        elif 'r' in self.mode:
            open_mode = os.O_RDONLY
        elif 'w' in self.mode and '+' in self.mode:
            open_mode = os.O_RDWR | os.O_TRUNC | os.O_CREAT
        elif 'w' in self.mode:
            open_mode = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        elif 'a' in self.mode and '+' in self.mode:
            open_mode = os.O_RDWR | os.O_CREAT
        elif 'a' in self.mode:
            open_mode = os.O_WRONLY | os.O_CREAT

        if open_mode is None:
            raise Exception('Undefined mode')

        try:
            self.file = self.smbfs.conn.open(self.smb_uri_path, open_mode)

            fstat = self.file.fstat()
            self.file_size = fstat[stat.ST_SIZE]

            if 'a' in self.mode:
                self.seek(0, fs.SEEK_END)

        except smbc.NoEntryError:
            raise ResourceNotFoundError(self.path)

    def _is_closed(self):
        return self.closed

    @synchronize
    def read(self, size=None):
        chunks = []
        if size is None or size < 0:
            while 1:
                data = self.file.read(self.blocksize)
                if not data:
                    break
                chunks.append(data)
                self.pos += len(data)
            return ''.join(chunks)

        remaining_bytes = size
        while remaining_bytes:
            read_size = min(remaining_bytes, self.blocksize)
            data = self.file.read(read_size)
            if not data:
                break
            chunks.append(data)
            self.pos += len(data)
            remaining_bytes -= len(data)

        return ''.join(chunks)

    @synchronize
    def write(self, data):

        data_pos = 0
        remaining_data = len(data)

        while remaining_data:
            chunk_size = min(remaining_data, self.blocksize)
            self.file.write(data[data_pos:data_pos + chunk_size])
            data_pos += chunk_size
            remaining_data -= chunk_size
            self.pos += chunk_size

    def flush(self):
        pass

    @synchronize
    def seek(self, pos, where=fs.SEEK_SET):
        if self.file_size is None:
            raise ValueError("Seek only works with files open for read")

        ret = self.file.seek(pos, where)
        self.pos = ret if ret != -1 else 0

    def tell(self):
        return self.pos

    @synchronize
    def truncate(self, size=None):
        # check that file is open for writing
        mode_was_found = False

        if ('w' in self.mode) or ('a' in self.mode) or ('r' in self.mode and '+' in self.mode):
            mode_was_found = True

        if not mode_was_found:
            raise IOError("File was opened only for reading")

        cur_mode = self.mode

        # reopen file if it is only for writing (not reading)
        for m in ['w', 'a']:
            if m in self.mode and '+' not in self.mode:
                self.close()
                self.mode = ''.join([m, '+'])
                self._open()

        if size is None:
            size = self.tell()

        self.seek(0)

        read_f = self.read(size)
        if read_f is not None:
            self.close()
            f = _SMBFile(self.smbfs, self.path, 'w')
            f.write(read_f)
            f.close()
        else:
            read_f = ''

        # reopen file again if it was reopened in mode for reading
        if cur_mode != self.mode:
            if not self._is_closed():
                self.close()
            self.mode = cur_mode

        if self._is_closed():
            self._open()

        # fill in the missing bytes
        if len(read_f) < size:
            self.write('\0' * (size - len(read_f)))

    @synchronize
    def close(self):
        self.file.close()
        self.closed = True

    @synchronize
    def next(self):
        endings = '\n'
        chars = []
        while True:
            char = self.read(1)
            if not char:
                if len(chars) == 0:
                    raise StopIteration
                else:
                    return ''.join(chars)
            else:
                chars.append(char)
                if char == endings:
                    return ''.join(chars)