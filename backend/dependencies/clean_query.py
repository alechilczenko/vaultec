"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

import re
from fastapi import HTTPException, Query
from typing import Annotated

def get_clean_query(q: Annotated[str, Query(min_length=2, max_length=100)]):

    if q is None:
        return None

    if re.search(r'[\x00-\x1f]', q):
        raise HTTPException(
            status_code=422, 
            detail="Null bytes or control characters are not allowed")

    if q.strip() in ["%", "_"]:
        raise HTTPException(
            status_code=422, 
            detail="Search query is too broad"
        )
    clean_q = " ".join(q.split())

    if not re.match(r'^[a-zA-Z0-9\s\-_.,()\[\]]+$', clean_q):
        raise HTTPException(
            status_code=422, 
            detail="Query contains restricted special characters")

    return clean_q