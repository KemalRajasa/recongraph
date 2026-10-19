// Replay paths from $src to $dst on the TEMPORAL graph: consecutive transitions (seq, seq + 1, ...),
// i.e. the order the log actually shows.
// Import: CALL apoc.import.graphml('temporal.graphml', {storeNodeIds: true, defaultRelationshipType: 'NEXT'})
// Params: $src, $dst = node `id`. Maximum length k = 8: edit *1..8.
MATCH p = (s {id: $src})-[:NEXT*1..8]->(d {id: $dst})
WITH p, relationships(p) AS r
WHERE all(i IN range(0, size(r) - 2) WHERE r[i + 1].seq = r[i].seq + 1)
RETURN [n IN nodes(p) | n.id] AS nodes, [x IN r | x.seq] AS seqs,
       [x IN r | x.t_src] AS t_src, [x IN r | x.t_dst] AS t_dst
ORDER BY seqs
