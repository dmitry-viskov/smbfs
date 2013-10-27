# -*- coding: utf-8 -*-
import unittest

from fs.tests import FSTestCases, ThreadingTestCases
from smbfs import SMBFS


class TestSMBFS(unittest.TestCase, FSTestCases, ThreadingTestCases):

    host = '192.168.1.36'
    share = 'test'
    username = 'linux'
    password = 'linux123'

    def setUp(self):
        self.fs = SMBFS(self.host, self.share, self.username, self.password)
        self._remove_dir_element('/')

    def _remove_dir_element(self, dir_path):
        if dir_path[-1] != '/':
            dir_path = ''.join([dir_path, '/'])

        data = self.fs.conn.opendir(self.fs.smb_path(dir_path)).getdents()

        for val in data:
            if val.name not in ['.', '..']:
                if int(val.smbc_type) == 7:
                    self._remove_dir_element(''.join([dir_path, val.name]))
                    self.fs.conn.rmdir(self.fs.smb_path(''.join([dir_path, val.name])))
                elif int(val.smbc_type) == 8:
                    self.fs.conn.unlink(self.fs.smb_path(''.join([dir_path, val.name])))

    def tearDown(self):
        self.fs.close()


if __name__ == "__main__":
    unittest.main() 
