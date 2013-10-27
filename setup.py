# -*- coding: utf-8 -*-
from setuptools import setup, find_packages


setup(name='smbfs',
      version='0.1',
      description=(u'OOP wrap to access SMB/CIFS storages using pyfilesystem library '
                   u'that implements filesystem abstractions'),
      long_description='',
      keywords='samba smb cifs pyfilesystem',
      author='Dmitry Viskov',
      author_email='strannik772@yandex.ru',
      maintainer='Dmitry Viskov',
      maintainer_email='strannik772@yandex.ru',
      url='https://github.com/StraNNiKK/smbfs',
      license='BSD',
      package_dir={'': 'src'},
      packages=find_packages('src'),
      include_package_data=True,
      package_data={},
      extras_require={'test': ['nose']},
      install_requires=[
                      'setuptools>=0.7.1',
                      'fs',
                      'pysmbc'
                     ],
      classifiers=(
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Operating System :: POSIX :: Linux',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2',
          'Topic :: Software Development :: Libraries :: Python Modules',
      )
)

