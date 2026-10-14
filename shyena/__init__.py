"""Shyena — the sharp-eyed hawk.

A code profiler that judges a repository on six dimensions in one scan: code
vulnerabilities, dependency vulnerabilities, licences, secrets, code smell and
compatibility. It is the ``code`` scope of the Knobly GRC core (the ``vapt`` package):
every engine is a GRC ``Probe``, every result is a GRC ``Finding``, every scan is a
GRC test instance persisted under ``runs/<id>/``.
"""

__version__ = "0.0.1"
