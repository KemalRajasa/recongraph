Changelog
=========

Unreleased
----------

- **Changed default:** ``--node=drain`` maps every row of the timeline under an event identity: ``Provider:EventID``
  for EVTX, ``data_type:timestamp_desc`` for structured artefacts, a Drain3 template for free text. Sigma stays an annotation on rows
  and nodes (``sigma_hits``, ``sigma_rules``, ``sigma_max_level``). ``--node=sigma`` reproduces the previous behavior,
  with byte-identical GraphML files.
- ``--export-csv`` has an ``event_key`` column; ``<graph>.meta.json`` records the configuration of each run.
- New dependency: ``drain3==0.9.11``.

v0.0.3
------

- Added Dockerfile for ReconGraph.

v0.0.2
------

- Added documentation for ReconGraph.
- Added test automation for ReconGraph.

v0.0.1
------

- Initial release of ReconGraph.
- Basic graph reconstruction functionality from log files.
- Support for weighted edges and anomaly highlighting.
- GraphML export support.
