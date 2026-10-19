// Baseline (R01 Definition 4): simple paths from $src to $dst on the AGGREGATE graph; no node repeats, time ignored.
// Import: CALL apoc.import.graphml('aggregate.graphml', {storeNodeIds: true, defaultRelationshipType: 'NEXT'})
// Params: $src, $dst = node `id`. Maximum length k = 8: edit *1..8.
MATCH p = (s {id: $src})-[:NEXT*1..8]->(d {id: $dst})
WHERE all(n IN nodes(p) WHERE single(m IN nodes(p) WHERE m = n))
RETURN [n IN nodes(p) | n.id] AS nodes, [x IN relationships(p) | x.weight] AS weights
ORDER BY size(nodes(p)), nodes
