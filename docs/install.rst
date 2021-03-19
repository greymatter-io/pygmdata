*******************
Installing pygmdata
*******************


Requirements
************

This library only supports Python 3.6+.
Usage with any other version is not supported and if it works, it is purely by accident.


Installing pygmdata
*******************

Installing the pygmdata library is extremely easy.
The package is currently in PyPi test and can be installed with ::

    pip install -i https://test.pypi.org/simple/ pygmdata


Verify Installation
*******************

The installation can be verified by making sure that your instance of Grey Matter Data is running.
Then running Python and hitting the ``self`` endpoint with the ``get_self()`` method::

    >> from pygmdata import Data
    >> d = pygmdata.Data("http://localhost:8181", USER_DN='CN=dave.borncamp,OU=Engineering,O=Untrusted Example,L=Baltimore,ST=MD,C=US')
    >> d.get_self()
    '{"label":"CN=dave.borncamp,OU=Engineering,O=Untrusted Example,L=Baltimore,ST=MD,C=US","exp":1608285907,"iss":"greymatter.io","values":{"email":["dave.borncamp@greymatter.io"],"org":["greymatter.io"]}}'

After that, you're all installed
