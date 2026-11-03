// All transitions that start within +-$w of a row with a high/critical Sigma annotation, on the TEMPORAL graph.
// The anchor time is the t_src of a transition leaving that row or the t_dst of one arriving at it.
// --node=drain: a node mixes annotated and other rows, so the level comes from the row (src_level, dst_level on the edge).
// --node=sigma: edges have no such attribute; all rows of a node share its label, so the node's level is used.
// Import: CALL apoc.import.graphml('temporal.graphml', {storeNodeIds: true, defaultRelationshipType: 'NEXT'})
// Params: $w = window in microseconds.
MATCH (u)-[a:NEXT]->(v)
UNWIND [{id: u.id, level: coalesce(a.src_level, u.level), t0: a.t_src_us},
        {id: v.id, level: coalesce(a.dst_level, v.level), t0: a.t_dst_us}] AS row
WITH row
WHERE row.level IN ['high', 'critical'] AND row.t0 IS NOT NULL
WITH DISTINCT row.id AS anchor, row.t0 AS t0
MATCH (x)-[e:NEXT]->(y)
WHERE e.t_src_us >= t0 - $w AND e.t_src_us <= t0 + $w
RETURN anchor, t0, e.seq AS seq, x.id AS src, y.id AS dst, e.t_src AS t_src, e.t_dst AS t_dst
ORDER BY anchor, t0, seq
