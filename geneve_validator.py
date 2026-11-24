"""Geneve (RFC 8926) TLV option validator.

Simulates hop-by-hop validation of a Geneve-encapsulated packet across
virtualization nodes. It does NOT craft or emit real Geneve packets; it
only parses option blobs and evaluates forwarding decisions against node
capabilities, a forwarding table and an MTU budget.

Python 3.8.2 compatible.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

# Wire overhead constants (bytes).
IPV4_HDR = 20
UDP_HDR = 8
GENEVE_BASE_HDR = 8
OPTION_HDR = 4  # class(2) + type(1) + length(1)

# Critical flag: top bit of the option Type byte.
CRITICAL_MASK = 0x80
TYPE_MASK = 0x7F
LENGTH_MASK = 0x1F  # low 5 bits of the length byte, in 4-octet units


class OptionParseError(Exception):
    """Raised when the raw TLV blob is malformed (e.g. length overrun)."""


class ValidationError(Exception):
    """Raised for semantic problems (duplicates, VNI conflict, MTU, ...)."""


@dataclass(frozen=True)
class GeneveOption:
    """A single parsed Geneve TLV option."""

    opt_class: int
    opt_type: int
    critical: bool
    payload: bytes

    @property
    def key(self) -> Tuple[int, int]:
        return (self.opt_class, self.opt_type)

    @property
    def wire_len(self) -> int:
        """Bytes occupied on the wire: header + 4-octet padded payload."""
        padded = (len(self.payload) + 3) & ~3
        return OPTION_HDR + padded


def parse_options(data: bytes) -> List[GeneveOption]:
    """Parse a raw Geneve option blob into GeneveOption objects.

    Raises OptionParseError if a declared option length runs past the end
    of the buffer or the header itself is truncated.
    """
    options: List[GeneveOption] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < OPTION_HDR:
            raise OptionParseError(
                "truncated option header at offset %d: %d byte(s) left"
                % (offset, len(data) - offset)
            )
        opt_class = (data[offset] << 8) | data[offset + 1]
        type_byte = data[offset + 2]
        critical = bool(type_byte & CRITICAL_MASK)
        opt_type = type_byte & TYPE_MASK
        declared = (data[offset + 3] & LENGTH_MASK) * 4
        payload_start = offset + OPTION_HDR
        payload_end = payload_start + declared
        if payload_end > len(data):
            raise OptionParseError(
                "option length out of bounds at offset %d: class=0x%04x "
                "type=%d declares %d payload byte(s), only %d remain"
                % (offset, opt_class, opt_type, declared,
                   len(data) - payload_start)
            )
        options.append(
            GeneveOption(
                opt_class=opt_class,
                opt_type=opt_type,
                critical=critical,
                payload=data[payload_start:payload_end],
            )
        )
        offset = payload_end
    return options


def build_options(options: Sequence[GeneveOption]) -> bytes:
    """Serialize options back to a wire blob (used by tests and the demo)."""
    blob = bytearray()
    for opt in options:
        padded = (len(opt.payload) + 3) & ~3
        if padded // 4 > LENGTH_MASK:
            raise OptionParseError("option payload too large for length field")
        blob += bytes(
            [
                (opt.opt_class >> 8) & 0xFF,
                opt.opt_class & 0xFF,
                opt.opt_type | (CRITICAL_MASK if opt.critical else 0),
                padded // 4,
            ]
        )
        blob += opt.payload
        blob += b"\x00" * (padded - len(opt.payload))
    return bytes(blob)


def check_duplicates(options: Sequence[GeneveOption]) -> None:
    """Reject repeated (class, type) options within one header."""
    seen: Set[Tuple[int, int]] = set()
    for opt in options:
        if opt.key in seen:
            raise ValidationError(
                "duplicate option class=0x%04x type=%d" % opt.key
            )
        seen.add(opt.key)


@dataclass
class Node:
    """A virtualization node (VTEP) with capabilities and local VNIs."""

    name: str
    capabilities: Set[Tuple[int, int]] = field(default_factory=set)
    vnis: Set[int] = field(default_factory=set)

    def supports(self, opt: GeneveOption) -> bool:
        return opt.key in self.capabilities


@dataclass(frozen=True)
class Route:
    """Forwarding-table entry installed on `node`.

    `match_option` optionally pins the route to packets carrying a given
    (class, type) option, which is how option content steers multipath.
    """

    node: str
    vni: int
    dst: str
    next_hop: Optional[str]  # None means local delivery
    match_option: Optional[Tuple[int, int]] = None


class ForwardingTable:
    def __init__(self, routes: Sequence[Route]):
        self._routes = list(routes)

    def lookup(
        self, node: str, vni: int, dst: str,
        option_keys: Set[Tuple[int, int]],
    ) -> Optional[Route]:
        """Most specific match wins: option-pinned routes beat plain ones."""
        best: Optional[Route] = None
        for route in self._routes:
            if route.node != node or route.vni != vni or route.dst != dst:
                continue
            if route.match_option is not None:
                if route.match_option not in option_keys:
                    continue
                return route  # option-specific match is the most specific
            if best is None:
                best = route
        return best


@dataclass
class HopResult:
    node: str
    action: str  # "forward" | "deliver" | "drop"
    reason: str
    ignored_options: List[Tuple[int, int]] = field(default_factory=list)
    rejected_options: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class ValidationResult:
    hops: List[HopResult] = field(default_factory=list)
    terminal_node: Optional[str] = None
    delivered: bool = False
    unsafe_options: List[Tuple[int, int]] = field(default_factory=list)
    error: Optional[str] = None


def encapsulation_overhead(options: Sequence[GeneveOption]) -> int:
    return (
        IPV4_HDR
        + UDP_HDR
        + GENEVE_BASE_HDR
        + sum(opt.wire_len for opt in options)
    )


def validate_packet(
    vni: int,
    src: str,
    dst: str,
    options: Sequence[GeneveOption],
    nodes: Dict[str, Node],
    ftable: ForwardingTable,
    mtu: int,
    inner_size: int,
    max_hops: int = 16,
) -> ValidationResult:
    """Walk the packet hop by hop from `src` towards `dst`."""
    result = ValidationResult()
    try:
        check_duplicates(options)
    except ValidationError as exc:
        result.error = str(exc)
        result.terminal_node = src
        result.hops.append(HopResult(src, "drop", result.error))
        return result

    overhead = encapsulation_overhead(options)
    if inner_size + overhead > mtu:
        result.error = (
            "MTU exceeded: inner %d + encapsulation overhead %d > MTU %d"
            % (inner_size, overhead, mtu)
        )
        result.terminal_node = src
        result.hops.append(HopResult(src, "drop", result.error))
        return result

    option_keys = {opt.key for opt in options}
    current = src
    for _ in range(max_hops):
        node = nodes[current]

        if vni not in node.vnis:
            reason = "VNI conflict: node %s does not serve VNI %d" % (
                current, vni)
            result.hops.append(HopResult(current, "drop", reason))
            result.terminal_node = current
            result.error = reason
            return result

        # Unknown critical options must be rejected; unknown non-critical
        # options are ignored but recorded so they stay visible in output.
        rejected = [o for o in options if o.critical and not node.supports(o)]
        ignored = [o for o in options
                   if not o.critical and not node.supports(o)]
        if rejected:
            reason = "unknown critical option(s) rejected: %s" % ", ".join(
                "class=0x%04x type=%d" % o.key for o in rejected)
            result.hops.append(HopResult(
                current, "drop", reason,
                ignored_options=[o.key for o in ignored],
                rejected_options=[o.key for o in rejected],
            ))
            result.terminal_node = current
            result.unsafe_options = [o.key for o in rejected]
            result.error = reason
            return result

        if current == dst:
            result.hops.append(HopResult(
                current, "deliver", "reached destination",
                ignored_options=[o.key for o in ignored],
            ))
            result.terminal_node = current
            result.delivered = True
            return result

        route = ftable.lookup(current, vni, dst, option_keys)
        if route is None:
            reason = "no route for VNI %d dst %s" % (vni, dst)
            result.hops.append(HopResult(
                current, "drop", reason,
                ignored_options=[o.key for o in ignored],
            ))
            result.terminal_node = current
            result.error = reason
            return result

        if route.next_hop is None or route.next_hop == current:
            result.hops.append(HopResult(
                current, "deliver", "local delivery",
                ignored_options=[o.key for o in ignored],
            ))
            result.terminal_node = current
            result.delivered = True
            return result

        result.hops.append(HopResult(
            current, "forward", "next hop %s" % route.next_hop,
            ignored_options=[o.key for o in ignored],
        ))
        current = route.next_hop
        if current not in nodes:
            result.error = "next hop %s is not a known node" % current
            result.terminal_node = current
            return result

    result.error = "hop limit exceeded"
    result.terminal_node = current
    return result


def check_roundtrip(
    outbound: Sequence[GeneveOption], inbound: Sequence[GeneveOption]
) -> List[str]:
    """Verify outbound and return paths carry consistent critical options."""
    errors: List[str] = []
    out_critical = {o.key for o in outbound if o.critical}
    in_critical = {o.key for o in inbound if o.critical}
    missing = out_critical - in_critical
    extra = in_critical - out_critical
    if missing:
        errors.append(
            "return path missing critical option(s): %s"
            % ", ".join("class=0x%04x type=%d" % k for k in sorted(missing))
        )
    if extra:
        errors.append(
            "return path added critical option(s): %s"
            % ", ".join("class=0x%04x type=%d" % k for k in sorted(extra))
        )
    return errors
