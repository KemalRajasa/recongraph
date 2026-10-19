// All transitions that start within +-$w of an occurrence of a high/critical event, on the TEMPORAL graph.
// An occurrence time is the t_src of a transition leaving the node or the t_dst of one arriving at it.
// Import: CALL apoc.import.graphml('temporal.graphml', {storeNodeIds: true, defaultRelationshipType: 'NEXT'})
// Params: $w = window in microseconds.
MATCH (h)-[a:NEXT]-()
WHERE h.level IN ['high', 'critical']
WITH DISTINCT h, CASE WHEN startNode(a) = h THEN a.t_src_us ELSE a.t_dst_us END AS t0
WHERE t0 IS NOT NULL
MATCH (x)-[e:NEXT]->(y)
WHERE e.t_src_us >= t0 - $w AND e.t_src_us <= t0 + $w
RETURN h.id AS anchor, t0, e.seq AS seq, x.id AS src, y.id AS dst, e.t_src AS t_src, e.t_dst AS t_dst
ORDER BY anchor, t0, seq
