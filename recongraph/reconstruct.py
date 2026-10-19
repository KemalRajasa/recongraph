"""Path reconstruction between two events of a ReconGraph graph.

Three path definitions, for a source node s, a destination node d and at most ``max_len`` edges:

- ``dfs``: simple paths s -> d in the aggregate graph (``nx.all_simple_paths``); no node repeats,
  time is ignored. This is the baseline.
- ``time``: time-respecting walks e1..em over the temporal graph (one edge per transition): e1 leaves s,
  em arrives at d, ``t_dst(e_i) <= t_src(e_{i+1})`` and, when ``max_gap_us`` is set,
  ``t_src(e_{i+1}) - t_dst(e_i) <= max_gap_us``. Nodes may repeat; an edge is used at most once;
  transitions without both timestamps are skipped. A walk may pass through d and continue.
- ``replay``: runs of consecutive transitions (``seq(e_{i+1}) = seq(e_i) + 1``), i.e. what the log shows.

A DFS path is *feasible* when at least one time-respecting walk follows the same node sequence,
otherwise *temporally impossible*.
"""
import argparse
import bisect
import json
import re
import sys
import time
from collections import defaultdict
from itertools import islice

import networkx as nx

DEFAULT_MAX_LEN = 8
DEFAULT_CAP = 1000


def load_graphs(temporal, aggregate=None):
    """(temporal MultiDiGraph, aggregate DiGraph) from GraphML paths or an EdgeGraph; node ids become strings."""
    if hasattr(temporal, "temporal_edges"):
        temporal.create_temporal_graph()
        T, A = temporal.T, temporal.G
    else:
        T = nx.read_graphml(temporal)
        A = nx.read_graphml(aggregate) if aggregate else None
    T = nx.relabel_nodes(T, str)
    A = nx.DiGraph(nx.relabel_nodes(A, str)) if A is not None else nx.DiGraph(T)
    return T, A


def label(G, node) -> str:
    event = str(G.nodes[node].get("event", node))
    return event.split(". ", 1)[1] if ". " in event else event


def resolve_node(G, query) -> str:
    """A node id, an exact label, or a case-insensitive substring of exactly one label."""
    query = str(query)
    if query in G:
        return query
    exact = [n for n in G if label(G, n) == query]
    hits = exact or [n for n in G if query.lower() in label(G, n).lower()]
    if len(hits) != 1:
        raise ValueError(f"{query!r} matches {len(hits)} nodes: {[label(G, n) for n in hits[:10]]}")
    return hits[0]


def _edges(T) -> dict:
    """{seq: (seq, u, v, t_src_us, t_dst_us)}."""
    return {d["seq"]: (d["seq"], u, v, d.get("t_src_us"), d.get("t_dst_us")) for u, v, d in T.edges(data=True)}


def _timed_out_edges(T) -> dict:
    """{node: edges leaving it that have both timestamps, sorted by t_src}."""
    out = defaultdict(list)
    for e in _edges(T).values():
        if e[3] is not None and e[4] is not None:
            out[e[1]].append(e)
    for edges in out.values():
        edges.sort(key=lambda e: (e[3], e[0]))
    return out


def dfs_paths(A, src, dst, max_len=DEFAULT_MAX_LEN, cap=DEFAULT_CAP):
    """([node list], truncated): simple paths in the aggregate graph, time ignored."""
    # networkx >= 3.5 yields the 0-edge path [src] when src == dst; a path needs at least one edge
    simple = (p for p in nx.all_simple_paths(A, src, dst, cutoff=max_len) if len(p) > 1)
    paths = list(islice(simple, cap + 1))
    return paths[:cap], len(paths) > cap


def time_respecting_paths(T, src, dst, max_len=DEFAULT_MAX_LEN, max_gap_us=None, cap=DEFAULT_CAP):
    """([seq list], truncated): time-respecting walks src -> dst, each temporal edge used at most once."""
    out = _timed_out_edges(T)
    starts = {n: [e[3] for e in edges] for n, edges in out.items()}
    # sound pruning: hops still needed to reach dst, ignoring time
    hops_to_dst = nx.single_source_shortest_path_length(nx.DiGraph(T).reverse(copy=False), dst) if dst in T else {}
    paths, used = [], set()

    def extend(path) -> bool:  # True once the cap is exceeded
        node, arrival = path[-1][2], path[-1][4]
        if node == dst:
            if len(paths) == cap:
                return True
            paths.append([e[0] for e in path])
        remaining = max_len - len(path)
        if remaining == 0 or node not in out:
            return False
        for e in out[node][bisect.bisect_left(starts[node], arrival):]:
            if max_gap_us is not None and e[3] - arrival > max_gap_us:
                break
            if e[0] in used or hops_to_dst.get(e[2], max_len + 1) > remaining - 1:
                continue
            used.add(e[0])
            stop = extend(path + [e])
            used.discard(e[0])
            if stop:
                return True
        return False

    for e in out.get(src, []):
        if hops_to_dst.get(e[2], max_len + 1) > max_len - 1:
            continue
        used.add(e[0])
        stop = extend([e])
        used.discard(e[0])
        if stop:
            return paths, True
    return paths, False


def replay_paths(T, src, dst, max_len=DEFAULT_MAX_LEN, cap=DEFAULT_CAP):
    """([seq list], truncated): runs of consecutive transitions src -> dst, the order the log shows."""
    by_seq = _edges(T)
    paths = []
    for seq in sorted(by_seq):
        run = [by_seq[seq]]
        if run[0][1] != src:
            continue
        while True:
            if run[-1][2] == dst:
                if len(paths) == cap:
                    return paths, True
                paths.append([e[0] for e in run])
            nxt = by_seq.get(run[-1][0] + 1)
            if len(run) == max_len or nxt is None or nxt[1] != run[-1][2]:
                break
            run.append(nxt)
    return paths, False


def is_feasible(T, node_path, max_gap_us=None, out=None) -> bool:
    """True when some time-respecting walk follows node_path, one temporal edge per hop."""
    out = out if out is not None else _timed_out_edges(T)
    arrivals = None  # arrival times reachable after the previous hop; None = no hop yet
    for u, v in zip(node_path, node_path[1:]):
        hop = [e for e in out.get(u, []) if e[2] == v]
        arrivals = {e[4] for e in hop if arrivals is None or any(
            a <= e[3] and (max_gap_us is None or e[3] - a <= max_gap_us) for a in arrivals)}
        if not arrivals:
            return False
    return True


def node_sequence(T, seqs, by_seq=None) -> list:
    by_seq = by_seq if by_seq is not None else _edges(T)
    return [by_seq[seqs[0]][1]] + [by_seq[s][2] for s in seqs]


def _timed(fn, *args, **kwargs):
    start = time.perf_counter()
    paths, truncated = fn(*args, **kwargs)
    return {"paths": paths, "truncated": truncated, "secs": round(time.perf_counter() - start, 4)}


def compare(T, A, src, dst, max_len=DEFAULT_MAX_LEN, max_gap_us=None, cap=DEFAULT_CAP,
            methods=("dfs", "time", "replay")) -> dict:
    """The requested methods; DFS paths are also split into feasible / temporally impossible."""
    result = {"src": src, "dst": dst, "max_len": max_len, "max_gap_us": max_gap_us, "cap": cap}
    if "dfs" in methods:
        result["dfs"] = _timed(dfs_paths, A, src, dst, max_len, cap)
        out = _timed_out_edges(T)
        result["dfs"]["feasible"] = [is_feasible(T, p, max_gap_us, out) for p in result["dfs"]["paths"]]
        n = len(result["dfs"]["paths"])
        result["dfs_impossible"] = n - sum(result["dfs"]["feasible"])
        result["dfs_impossible_pct"] = round(100 * result["dfs_impossible"] / n, 1) if n else None
    if "time" in methods:
        result["time"] = _timed(time_respecting_paths, T, src, dst, max_len, max_gap_us, cap)
    if "replay" in methods:
        result["replay"] = _timed(replay_paths, T, src, dst, max_len, cap)
    return result


def describe(T, result: dict) -> dict:
    """JSON-friendly copy of a result with labels and timestamps instead of bare ids/seqs."""
    by_seq = {d["seq"]: (u, v, d) for u, v, d in T.edges(data=True)}

    def edge(seq):
        u, v, d = by_seq[seq]
        return {"seq": seq, "src": label(T, u), "dst": label(T, v), "t_src": d.get("t_src"), "t_dst": d.get("t_dst"),
                "src_row": d.get("src_row"), "dst_row": d.get("dst_row")}

    out = {k: v for k, v in result.items() if k not in ("dfs", "time", "replay")}
    out["src_label"], out["dst_label"] = label(T, result["src"]), label(T, result["dst"])
    for method in ("dfs", "time", "replay"):
        if method not in result:
            continue
        r = dict(result[method])
        if method == "dfs":
            r["paths"] = [[label(T, n) for n in p] for p in r["paths"]]
        else:
            r["paths"] = [[edge(s) for s in p] for p in r["paths"]]
        out[method] = r
    return out


def parse_duration(text) -> int:
    """'60s', '500ms', '2m', '1h', '250us' or plain seconds -> microseconds."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(us|ms|s|m|h)?\s*", str(text))
    if not m:
        raise argparse.ArgumentTypeError(f"invalid duration: {text!r}")
    factor = {"us": 1, "ms": 1_000, "s": 1_000_000, "m": 60_000_000, "h": 3_600_000_000}[m.group(2) or "s"]
    return int(float(m.group(1)) * factor)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reconstruct paths between two events of a ReconGraph graph.")
    parser.add_argument("--temporal", required=True, help="temporal GraphML (recongraph --temporal-output)")
    parser.add_argument("--agg", help="aggregate GraphML (-o); default: aggregate built from --temporal")
    parser.add_argument("--src", required=True, help="source node: id, exact label or unique label substring")
    parser.add_argument("--dst", required=True, help="destination node: id, exact label or unique label substring")
    parser.add_argument("--mode", choices=["dfs", "time", "replay", "compare"], default="compare")
    parser.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN, help="maximum number of edges")
    parser.add_argument("--max-gap", type=parse_duration, default=None, help="time mode: maximum wait between transitions, e.g. 60s")
    parser.add_argument("--cap", type=int, default=DEFAULT_CAP, help="maximum number of paths per method")
    parser.add_argument("--out", help="write the full result as JSON")
    args = parser.parse_args(argv)

    T, A = load_graphs(args.temporal, args.agg)
    try:
        src, dst = resolve_node(T, args.src), resolve_node(T, args.dst)
    except ValueError as e:
        parser.error(str(e))
    methods = ("dfs", "time", "replay") if args.mode == "compare" else (args.mode,)
    described = describe(T, compare(T, A, src, dst, args.max_len, args.max_gap, args.cap, methods))
    print(f"{described['src_label']} -> {described['dst_label']} (max_len={args.max_len}, max_gap_us={args.max_gap}, cap={args.cap})")
    for method in ("dfs", "time", "replay"):
        if method in described:
            r = described[method]
            print(f"  {method:6}: {len(r['paths'])} paths{' (truncated)' if r['truncated'] else ''}, {r['secs']} s")
    if "dfs" in described and described["dfs"]["paths"]:
        print(f"  dfs paths temporally impossible: {described['dfs_impossible']} ({described['dfs_impossible_pct']}%)")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(described, f, indent=1)
        print(f"  written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
