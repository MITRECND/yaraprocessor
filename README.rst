Yaraprocessor
=============

`YARA <http://code.google.com/p/yara-project/>`_ is an awesome tool.
It's aimed at helping malware researchers to identify and classify malware
samples. With YARA you can create descriptions of malware families based
on textual or binary patterns contained on samples of those families.

However, sometimes the data you are analyzing needs some manipulation in
order to achieve the best results. Yaraprocessor allows you to scan data
streams in few unique ways. It supports scanning data streams in discrete
chunks, or buffers. These chunks can overlap or be completely disjoint
depending on the 'processing_mode' selected.

Yaraprocessor was originally written for 
`Chopshop <https://github.com/MITRECND/chopshop>`_. Combined with Chopshop, it
allows for dynamic scanning of payloads plucked from network packet capture.
Historically, signature based tools operate over the entire PCAP file. With
Chopshop and Yaraprocessor, YARA can be ran against individual packet payloads
as well as a concatenation of some or all of the payloads. Ideally, this makes
writting signatures easier.

Dependencies
------------

- `Python 2.7 <http://www.python.org/download/releases/2.7.3/>`_
- `YARA <http://code.google.com/p/yara-project/>`_
- `YARA-python bindings <http://code.google.com/p/yara-project/>`_

Installation
------------

Simply clone the repository via git:

.. code-block:: bash

    $ git clone https://github.com/MITRECND/yaraprocessor.git

Or download the latest release from our `github page
<https://github.com/MITRECND/yaraprocessor/archive/master.zip>`_.

Once you have the code, run the following command inside the
Yaraprocessor directory:

.. code-block:: bash

    $ python setup.py install
