"""Local Mail Cleaner - a local, read-only newsletter subscription scanner.

Stage A: read-only scanner and subscription table.
Mailbox-changing features (unsubscribe, moving messages, quarantine) belong to
later stages and are deliberately absent from this code base.
"""

__version__ = "0.1.0"

#: Implementation stage. Stage B/C features must not be enabled in stage "A".
STAGE = "A"

#: Hard feature switches. They are constants on purpose: there is no code path
#: that performs these actions in stage A, and tests assert they stay False.
UNSUBSCRIBE_ENABLED = False
QUARANTINE_ENABLED = False
