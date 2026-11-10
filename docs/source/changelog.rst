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
- **Changed output:** each run writes to one folder, ``-o``/``--output-dir`` (default ``recongraph_output/<input>_<node mode>``), with
  ``recongraph_agg.graphml``, ``recongraph_temporal.graphml`` and ``recongraph_meta.json`` always present. ``--export-events`` replaces
  ``--export-csv``, ``--export-sigma`` takes no value, ``--temporal-output`` is removed, and ``recongraph_meta.json`` replaces the
  ``<graph>.meta.json`` files mentioned above. An earlier run in the folder stops the run unless ``--overwrite`` is given.

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
