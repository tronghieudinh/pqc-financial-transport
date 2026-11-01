#!/usr/bin/env python3
"""
tbnet.py - network namespaces, veth links, tc netem shaping and TCP route metrics for the testbed.

Needs root (run through `sudo`). Topologies (all IPv6, so that the headers are exactly the 40 + 20 bytes
that the model assumes; TCP timestamps are switched off, so MSS = MTU - 60):

  direct :  client ns [pqcc] --vc0 ==== vs0-- server ns [pqcs]
  proxy  :  client ns [pqcc] --vc0 ==== vp0-- proxy ns [pqcp] --vp1 ==== vs0-- server ns [pqcs]

The link under test is always the client link (vc0 <-> peer). netem is installed on the egress of both
ends, each with delay RTT/2, so that the round-trip time is RTT; `rate` and `loss` apply per direction.
GSO/TSO/GRO are off, so that every segment travels as its own packet.
Per-peer host routes carry initcwnd, initrwnd, congestion control (reno: the model is slow-start
ACK-clocked) and quickack; they are replaced per configuration.
"""
from __future__ import annotations

import shlex
import os
import subprocess
import sys

NS_C, NS_P, NS_S = "pqcc", "pqcp", "pqcs"
A_C1, A_P1 = "fd99:1::1", "fd99:1::2"        # client link: client, peer (server or proxy)
A_P2, A_S2 = "fd99:2::1", "fd99:2::2"        # proxy-server link: proxy, server
PROBE_PORT = "4433"


class Testbed:
    def __init__(self, topology: str = "direct", dry_run: bool = False, verbose: bool = False, timestamps: bool = False):
        assert topology in ("direct", "proxy")
        self.topology = topology
        self.dry = dry_run
        self.timestamps = timestamps         # TCP timestamps on: 12 option bytes per segment, MSS = MTU - 72
        self.verbose = verbose or dry_run
        self.ns = [NS_C, NS_S] if topology == "direct" else [NS_C, NS_P, NS_S]

    # ------------------------------------------------------------------ plumbing
    def run(self, cmd, ns=None, check=True, capture=False):
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        if ns:
            cmd = ["ip", "netns", "exec", ns] + cmd
        if self.verbose:
            print("+", " ".join(shlex.quote(c) for c in cmd), file=sys.stderr)
        if self.dry:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.run(cmd, check=check, capture_output=capture, text=True)

    def exec_prefix(self, who: str) -> list:
        return ["ip", "netns", "exec", {"c": NS_C, "p": NS_P, "s": NS_S}[who]]

    @property
    def client_target(self) -> str:             # address the client connects to
        return A_P1

    @property
    def server_bind(self) -> str:               # address the probe server listens on
        return A_P1 if self.topology == "direct" else A_S2

    # ------------------------------------------------------------------ build / tear down
    def down(self):
        for ns in (NS_C, NS_P, NS_S):
            self.run(["ip", "netns", "del", ns], check=False, capture=True)

    def up(self):
        self.down()
        for ns in self.ns:
            self.run(["ip", "netns", "add", ns])
            self.run(["ip", "link", "set", "lo", "up"], ns=ns)
            for k, v in (("net.ipv6.conf.all.disable_ipv6", "0"), ("net.ipv6.conf.default.disable_ipv6", "0"),
                         ("net.ipv6.conf.all.accept_dad", "0"), ("net.ipv6.conf.default.accept_dad", "0"),
                         ("net.ipv4.tcp_timestamps", "1" if self.timestamps else "0"),   # off: MSS = MTU - 60 (model: 40 + 20 header bytes)
                         ("net.ipv4.tcp_no_metrics_save", "1")):
                self.run(["sysctl", "-q", "-w", f"{k}={v}"], ns=ns)
            if os.environ.get("PQC_RMEM"):        # WP6 rwnd test: receive buffer "min default max" (per namespace where the kernel allows it, else global)
                self.run(["sysctl", "-q", "-w", f"net.ipv4.tcp_rmem={os.environ['PQC_RMEM']}"], ns=ns, check=False)
        if self.topology == "direct":
            self._link(NS_C, "vc0", A_C1, NS_S, "vs0", A_P1)
        else:
            self._link(NS_C, "vc0", A_C1, NS_P, "vp0", A_P1)
            self._link(NS_P, "vp1", A_P2, NS_S, "vs0", A_S2)

    def _link(self, ns1, if1, addr1, ns2, if2, addr2):
        self.run(["ip", "link", "add", if1, "type", "veth", "peer", "name", if2])
        for ns, ifc, addr in ((ns1, if1, addr1), (ns2, if2, addr2)):
            self.run(["ip", "link", "set", ifc, "netns", ns])
            self.run(["ip", "-6", "addr", "add", f"{addr}/64", "dev", ifc, "nodad"], ns=ns)
            self.run(["ip", "link", "set", ifc, "up"], ns=ns)
            self.run(["ethtool", "-K", ifc, "tso", "off", "gso", "off", "gro", "off", "lro", "off"], ns=ns, check=False,
                     capture=True)

    # ------------------------------------------------------------------ per-configuration shaping
    def _links(self):
        """(namespace, interface, peer address) of every interface that carries a host route."""
        if self.topology == "direct":
            return [(NS_C, "vc0", A_P1), (NS_S, "vs0", A_C1)]
        return [(NS_C, "vc0", A_P1), (NS_P, "vp0", A_C1), (NS_P, "vp1", A_S2), (NS_S, "vs0", A_P2)]

    def shape(self, rtt_ms: float, rate_mbps: float, loss_pct: float, mtu: int, icw: int, cc: str = "reno",
              initrwnd: int = 100, quickack: bool = True):
        """Apply one network configuration. rtt_ms = rate_mbps = loss_pct = 0 means 'unshaped'."""
        shaped = rtt_ms > 0 or rate_mbps > 0 or loss_pct > 0
        client_link = [(NS_C, "vc0"), (NS_S if self.topology == "direct" else NS_P,
                                      "vs0" if self.topology == "direct" else "vp0")]
        for ns, ifc, _peer in self._links():
            self.run(["ip", "link", "set", "dev", ifc, "mtu", str(mtu)], ns=ns)
        for ns, ifc in client_link:
            if not shaped:
                self.run(["tc", "qdisc", "del", "dev", ifc, "root"], ns=ns, check=False, capture=True)
                continue
            cmd = ["tc", "qdisc", "replace", "dev", ifc, "root", "netem", "limit", "100000"]
            if rtt_ms > 0:
                cmd += ["delay", f"{rtt_ms / 2:g}ms"]
            if loss_pct > 0:
                cmd += ["loss", f"{loss_pct:g}%"]
            if rate_mbps > 0:
                cmd += ["rate", f"{rate_mbps:g}mbit"]
            self.run(cmd, ns=ns)
        for ns, ifc, peer in self._links():
            route = ["ip", "-6", "route", "replace", f"{peer}/128", "dev", ifc,
                     "initcwnd", str(icw), "initrwnd", str(initrwnd), "congctl", cc]
            if quickack:
                route += ["quickack", "1"]
            self.run(route, ns=ns)
            self.run(["ip", "tcp_metrics", "flush"], ns=ns, check=False, capture=True)

    def smoke_test(self) -> bool:
        """Ping the peer through the client link (needs the configuration to be applied)."""
        r = self.run(["ping", "-6", "-c", "2", "-W", "3", A_P1], ns=NS_C, check=False, capture=True)
        return r.returncode == 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description="build / tear down the testbed namespaces by hand")
    ap.add_argument("action", choices=["up", "down", "shape"])
    ap.add_argument("--topology", default="direct", choices=["direct", "proxy"])
    ap.add_argument("--rtt", type=float, default=0)
    ap.add_argument("--rate", type=float, default=0)
    ap.add_argument("--loss", type=float, default=0)
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--icw", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    tb = Testbed(a.topology, dry_run=a.dry_run, verbose=True)
    if a.action == "up":
        tb.up()
    elif a.action == "down":
        tb.down()
    else:
        tb.shape(a.rtt, a.rate, a.loss, a.mtu, a.icw)


if __name__ == "__main__":
    main()
