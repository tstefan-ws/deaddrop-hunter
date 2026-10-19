"""Indexed data providers (Etherscan V2, Dune) used where plain RPC cannot search."""


class ProviderUnavailable(Exception):
    """Raised when a provider cannot be used (e.g. missing API key). Callers skip gracefully."""
