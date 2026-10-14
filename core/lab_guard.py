"""Refuse to send fuzz traffic anywhere but a lab address.

The README says lab only; this makes the default match. Loopback, RFC 1918,
link-local and unique-local addresses pass. Anything else needs an explicit
allow_public=True from the caller.
"""
import ipaddress
import socket


class LabGuardError(RuntimeError):
    pass


def _is_lab_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%")[0])
    return ip.is_loopback or ip.is_private or ip.is_link_local


def assert_lab_target(host: str, allow_public: bool = False) -> None:
    if allow_public:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise LabGuardError(f"cannot resolve {host!r}: {exc}") from exc
    addrs = {info[4][0] for info in infos}
    public = sorted(a for a in addrs if not _is_lab_address(a))
    if public:
        raise LabGuardError(
            f"{host} resolves to non-lab address(es) {public}. "
            "Pass allow_public=True only for systems you are authorized to test."
        )
