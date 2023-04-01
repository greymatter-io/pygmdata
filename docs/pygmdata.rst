========
PyGMData
========

The actual greymatter Data interface class for Python.
This works by keeping an internal representation of the Data file structure in a flat store which has the resource and the OID.
It then calls out to the Data API using REST and the OID for a target resource.

It supports using TLS connections to a mesh.
In this case, a `USER_DN` is not expected to be in the headers as it will be over-written by the edge node and the DN from the cert will be used instead.

``pygmdata``
------------

.. autoclass:: pygmdata.pygmdata.Data
   :members:
