// Time-respecting paths from $src to $dst on the TEMPORAL graph (one :NEXT per transition).
// Import: CALL apoc.import.graphml('temporal.graphml', {storeNodeIds: true, defaultRelationshipType: 'NEXT'})
// Params: $src, $dst = node `id`; $gap = maximum wait in microseconds between transitions, or null.
// Maximum length k = 8: Cypher cannot parameterize it, edit *1..8.
// Nodes may repeat; Cypher never reuses a relationship within one path.
MATCH p = (s {id: $src})-[:NEXT*1..8]->(d {id: $dst})
WITH p, relationships(p) AS r
WHERE all(x IN r WHERE x.t_src_us IS NOT NULL AND x.t_dst_us IS NOT NULL)
  AND all(i IN range(0, size(r) - 2) WHERE r[i].t_dst_us <= r[i + 1].t_src_us
          AND ($gap IS NULL OR r[i + 1].t_src_us - r[i].t_dst_us <= $gap))
RETURN [n IN nodes(p) | n.id] AS nodes, [x IN r | x.seq] AS seqs,
       [x IN r | x.t_src] AS t_src, [x IN r | x.t_dst] AS t_dst
ORDER BY size(r), seqs
