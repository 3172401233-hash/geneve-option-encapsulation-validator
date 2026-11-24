import unittest

from geneve_validator import (
    ForwardingTable,
    GeneveOption,
    Node,
    OptionParseError,
    Route,
    build_options,
    check_roundtrip,
    encapsulation_overhead,
    parse_options,
    validate_packet,
)

VNI = 100
MTU = 1500
INNER = 1400

# Option keys used across the tests.
OPT_A = (0x0100, 1)  # known to node-a only
OPT_B = (0x0100, 2)  # known to node-b only
OPT_UNKNOWN_CRIT = (0xFFFF, 9)
OPT_UNKNOWN_BENIGN = (0xFFFF, 10)


def opt(key, critical=False, payload=b"\x01\x02\x03\x04"):
    return GeneveOption(opt_class=key[0], opt_type=key[1],
                        critical=critical, payload=payload)


def make_nodes():
    return {
        "node-a": Node("node-a", capabilities={OPT_A, OPT_B}, vnis={VNI}),
        "node-b": Node("node-b", capabilities={OPT_A}, vnis={VNI}),
        "node-c": Node("node-c", capabilities={OPT_A, OPT_B}, vnis={VNI}),
    }


def make_ftable():
    # Default path: a -> b -> c. Option OPT_A pins traffic to the direct
    # a -> c link, which is how option content steers multipath.
    return ForwardingTable([
        Route("node-a", VNI, "node-c", "node-b"),
        Route("node-a", VNI, "node-c", "node-c", match_option=OPT_A),
        Route("node-b", VNI, "node-c", "node-c"),
    ])


class TestParseOptions(unittest.TestCase):
    def test_roundtrip_serialization(self):
        options = [opt(OPT_A, critical=True), opt(OPT_B)]
        parsed = parse_options(build_options(options))
        self.assertEqual([o.key for o in parsed], [OPT_A, OPT_B])
        self.assertTrue(parsed[0].critical)
        self.assertFalse(parsed[1].critical)
        self.assertEqual(parsed[0].payload, b"\x01\x02\x03\x04")

    def test_length_out_of_bounds(self):
        # Declares 8 bytes of payload but only 4 are present.
        blob = bytes([0x01, 0x00, 0x01, 0x02]) + b"\x01\x02\x03\x04"
        with self.assertRaises(OptionParseError):
            parse_options(blob)

    def test_truncated_header(self):
        with self.assertRaises(OptionParseError):
            parse_options(b"\x01\x00\x01")

    def test_critical_bit_decoded_from_type_byte(self):
        blob = bytes([0x00, 0x01, 0x80 | 0x05, 0x00])
        parsed = parse_options(blob)
        self.assertEqual(parsed[0].opt_type, 0x05)
        self.assertTrue(parsed[0].critical)


class TestValidatePacket(unittest.TestCase):
    def test_unknown_critical_option_rejected(self):
        nodes = make_nodes()
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_UNKNOWN_CRIT, critical=True)],
            nodes, make_ftable(), MTU, INNER,
        )
        self.assertFalse(result.delivered)
        self.assertEqual(result.terminal_node, "node-a")
        self.assertEqual(result.unsafe_options, [OPT_UNKNOWN_CRIT])
        self.assertIn("critical", result.error)
        self.assertEqual(result.hops[0].action, "drop")

    def test_unknown_noncritical_ignored_but_recorded(self):
        nodes = make_nodes()
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_A, critical=True), opt(OPT_UNKNOWN_BENIGN)],
            nodes, make_ftable(), MTU, INNER,
        )
        self.assertTrue(result.delivered)
        self.assertEqual(result.terminal_node, "node-c")
        # The benign unknown option must stay visible on every hop.
        for hop in result.hops:
            self.assertIn(OPT_UNKNOWN_BENIGN, hop.ignored_options)
        self.assertEqual(result.unsafe_options, [])

    def test_critical_option_rejected_mid_path(self):
        # node-a knows OPT_A and forwards, node-b does not -> drop at b.
        nodes = make_nodes()
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_B, critical=True)],
            nodes, make_ftable(), MTU, INNER,
        )
        self.assertFalse(result.delivered)
        self.assertEqual(result.terminal_node, "node-b")
        self.assertEqual(result.unsafe_options, [OPT_B])
        self.assertEqual([h.action for h in result.hops],
                         ["forward", "drop"])

    def test_duplicate_tlv_rejected(self):
        nodes = make_nodes()
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_A, critical=True), opt(OPT_A, critical=True)],
            nodes, make_ftable(), MTU, INNER,
        )
        self.assertFalse(result.delivered)
        self.assertEqual(result.terminal_node, "node-a")
        self.assertIn("duplicate", result.error)

    def test_mtu_exceeded(self):
        nodes = make_nodes()
        overhead = encapsulation_overhead([opt(OPT_A, critical=True)])
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_A, critical=True)],
            nodes, make_ftable(), MTU, MTU - overhead + 1,
        )
        self.assertFalse(result.delivered)
        self.assertIn("MTU", result.error)

    def test_mtu_exact_fit_passes(self):
        nodes = make_nodes()
        overhead = encapsulation_overhead([opt(OPT_A, critical=True)])
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_A, critical=True)],
            nodes, make_ftable(), MTU, MTU - overhead,
        )
        self.assertTrue(result.delivered)

    def test_vni_conflict(self):
        nodes = make_nodes()
        nodes["node-b"].vnis = {200}  # node-b does not serve VNI 100
        result = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_B, critical=True)],
            nodes, make_ftable(), MTU, INNER,
        )
        self.assertFalse(result.delivered)
        self.assertEqual(result.terminal_node, "node-b")
        self.assertIn("VNI conflict", result.error)

    def test_multipath_option_steers_route(self):
        nodes = make_nodes()
        ftable = make_ftable()
        # Without OPT_A: default path a -> b -> c (3 hops).
        plain = validate_packet(
            VNI, "node-a", "node-c", [], nodes, ftable, MTU, INNER)
        self.assertEqual([h.node for h in plain.hops],
                         ["node-a", "node-b", "node-c"])
        self.assertTrue(plain.delivered)
        # With OPT_A: pinned route a -> c directly (2 hops).
        steered = validate_packet(
            VNI, "node-a", "node-c",
            [opt(OPT_A, critical=True)], nodes, ftable, MTU, INNER)
        self.assertEqual([h.node for h in steered.hops],
                         ["node-a", "node-c"])
        self.assertTrue(steered.delivered)

    def test_no_route_drops(self):
        nodes = make_nodes()
        result = validate_packet(
            VNI, "node-a", "node-c", [],
            nodes, ForwardingTable([]), MTU, INNER,
        )
        self.assertFalse(result.delivered)
        self.assertIn("no route", result.error)


class TestRoundtrip(unittest.TestCase):
    def test_consistent_roundtrip(self):
        outbound = [opt(OPT_A, critical=True), opt(OPT_UNKNOWN_BENIGN)]
        inbound = [opt(OPT_A, critical=True)]
        self.assertEqual(check_roundtrip(outbound, inbound), [])

    def test_return_path_missing_critical(self):
        outbound = [opt(OPT_A, critical=True)]
        inbound = []
        errors = check_roundtrip(outbound, inbound)
        self.assertEqual(len(errors), 1)
        self.assertIn("missing", errors[0])

    def test_return_path_added_critical(self):
        outbound = []
        inbound = [opt(OPT_B, critical=True)]
        errors = check_roundtrip(outbound, inbound)
        self.assertEqual(len(errors), 1)
        self.assertIn("added", errors[0])


if __name__ == "__main__":
    unittest.main()
