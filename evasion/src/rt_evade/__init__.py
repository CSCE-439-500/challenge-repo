"""rt_evade: Modular red-team static ML evasion toolkit.

This package provides in-memory binary transformation primitives and pipelines
tailored for static ML evasion exercises. All operations are guarded by ROE
controls and avoid writing decoded artifacts to disk by default.
"""

__all__ = [
    "core",
    "pe",
    "dropper",
]
