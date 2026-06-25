"""
control — Control Layer package for the Rogue IoT Detector.

Re-exports the primary quarantine API so callers can write::

    from control import quarantine_device, get_quarantine_log
"""

from control.quarantine import quarantine_device, get_quarantine_log

__all__ = ["quarantine_device", "get_quarantine_log"]
