"""Optional framework adapters. Each submodule imports its framework lazily (only when its
adapter class is constructed, not at package import time) so ``pip install ledger-sdk`` alone
never requires langchain/crewai/autogen/openhands to be installed. Install the matching extra
to use one, e.g. ``pip install ledger-sdk[langchain]``.
"""
