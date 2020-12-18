========
PyGMData
========

The actual Grey Matter Data interface class for Python.
This works by keeping an internal representation of the Data file structure in a flat store which has the resource and the OID.
It then calls out to the Data API using REST and the OID for a target resource.

``pygmdata``
------------

.. autoclass:: pygmdata.pygmdata.Data
   :members:
