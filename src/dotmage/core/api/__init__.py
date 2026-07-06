"""Endpoint specifications.

Pure builders that describe *what* request to make (method, path, body) without performing
any I/O. Both the sync and async facades execute these, so the endpoint contract lives in one
place (:mod:`dotmage.core.api.spec`).
"""

from dotmage.core.api import spec
from dotmage.core.api.spec import RequestSpec

__all__ = ["RequestSpec", "spec"]
