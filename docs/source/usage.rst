Usage
=====

Command Line Interface
----------------------

ReconGraph can be used from the command line to process Plaso CSV files or raw logs.

.. code-block:: bash

   recongraph [-h] -f FILE [-o DIR] [-r RULES] [--export-events] [--export-sigma] [--overwrite] [--strict] [--keep-all-timestamps]
              [--edge-order {time,file}] [--node {drain,sigma}]
              [--exclude-status STATUS[,STATUS...]] [--exclude-rules-file FILE]

Arguments:
^^^^^^^^^^

*   ``-f``, ``--file``: Path to the input log file (**Plaso CSV**, **Plaso JSON Lines** from ``psort -o json_line``, or raw TXT). **Required**.
*   ``-o``, ``--output-dir``: Folder of this run, created if missing (default: ``recongraph_output/<input>_<node mode>``).
*   ``-r``, ``--rules``: Path to the directory containing **Sigma rules** (.yml files).
*   ``--export-events``: Also write the log rows of every graph node to ``recongraph_events.csv``.
*   ``--export-sigma``: Also write the input with its Sigma annotation to ``recongraph_sigma.csv``.
*   ``--overwrite``: Replace the output of an earlier run in the folder. Without it the run stops before writing. Other files are kept.
*   ``--strict``: Strict logsource validation (category, product and service must match). Flexible mode (default) only
    checks ``product`` and lets only keyword selections fall back to the whole message.
    ``--export-sigma`` writes ``sigma`` (primary label), ``sigma_all`` (every matching rule), ``sigma_ids`` (their rule IDs, sorted),
    ``sigma_tactics`` and ``sigma_techniques`` (the union of their ATT&CK tags).
*   ``--keep-all-timestamps``: JSON Lines input only. Keep every timestamp row of an EVTX record instead of only ``Creation Time``.
*   ``--edge-order {time,file}``: Order transitions by timestamp (default; ties keep row order, rows without a valid
    timestamp stay right after the row they follow) or by input row order (the original behavior).
*   ``--node {drain,sigma}``: Node identity (default ``drain``), see below.
*   ``--exclude-status``: Do not load rules with these statuses, comma separated (ex: ``deprecated,unsupported``).
*   ``--exclude-rules-file``: Do not load rules whose ``id`` is listed in this file (format of Hayabusa ``exclude_rules.txt``: one UUID per line, ``#`` starts a comment).

Node modes:
^^^^^^^^^^^

.. note::
   The default changed. ReconGraph used to map only rows with a Sigma label. ``--node=drain`` is now the default and maps
   every row; ``--node=sigma`` reproduces the old behavior, with byte-identical GraphML files.

*   ``--node=drain``: every row is part of the graph, under an event identity (``event_key``):
    ``Provider:EventID`` for EVTX; ``data_type:timestamp_desc`` for structured artefacts; ``data_type:template`` for free
    text, with a template mined by
    `Drain3 <https://github.com/logpai/Drain3>`_. Sigma still runs on every raw row and is stored as an annotation.
*   ``--node=sigma``: the node is the primary Sigma label and only labeled rows are mapped. Useful only for sources that
    have Sigma rules; the graph of a source without rules is empty.

ReconGraph maps events and does not judge them. A Sigma annotation is a starting point for a query; the investigator
decides which events are of interest. See :doc:`data_format` for the attributes and identity rules.

Each run writes to one folder, in both node modes and also when the graphs are empty: ``recongraph_agg.graphml`` (``weight``,
``first_seen``/``last_seen``, ``delta_min_us``/``delta_median_us``/``delta_max_us``), ``recongraph_temporal.graphml`` (one edge per
transition: ``seq``, ``t_src``/``t_dst`` and their ``_us`` epoch microseconds, ``delta_us``, ``src_row``/``dst_row``) and
``recongraph_meta.json`` with the run's configuration (node mode, edge order, input file, rule
path, how each source was treated with its row count, Drain3 configuration and snapshots). The same input and configuration give the same GraphML.

Example:
^^^^^^^^

.. code-block:: bash

   recongraph -f forensic_timeline.csv -r ./sigma_rules/
   recongraph -f forensic_timeline.csv -r ./sigma_rules/ --node=sigma

For Windows event logs, JSON Lines input exposes the named EVTX fields (``Image``, ``CommandLine``, ``TargetImage``, ...)
that field-based Sigma rules need:

.. code-block:: bash

   psort.py -o json_line -w timeline.jsonl timeline.plaso
   recongraph -f timeline.jsonl -r ./sigma/rules/windows --strict

Running with Docker
-------------------

If you installed ReconGraph via Docker, you can run the same CLI commands by passing arguments directly to the container.
The working directory inside the container is ``/app/data``, so mount your local data folder there to read inputs and retrieve outputs.

Basic usage
^^^^^^^^^^^

.. code-block:: bash

   # Linux / macOS
   docker run --rm -v "$(pwd)/data:/app/data" recongraph -f forensic_timeline.csv

   # Windows (PowerShell)
   docker run --rm -v "${PWD}\data:/app/data" recongraph -f forensic_timeline.csv

Full example with all output flags
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Linux / macOS
   docker run --rm -v "$(pwd)/data:/app/data" recongraph \
     -f forensic_timeline.csv \
     -o result \
     --export-events \
     --export-sigma

   # Windows (PowerShell)
   docker run --rm -v "${PWD}\data:/app/data" recongraph `
     -f forensic_timeline.csv `
     -o result `
     --export-events `
     --export-sigma

This will produce the following files inside ``data/result/``:

- ``recongraph_agg.graphml`` — the aggregate graph
- ``recongraph_temporal.graphml`` — the graph with one edge per transition
- ``recongraph_meta.json`` — the configuration of the run
- ``recongraph_events.csv`` — detailed event log entries
- ``recongraph_sigma.csv`` — input log annotated with Sigma rule matches

Using custom Sigma rules
^^^^^^^^^^^^^^^^^^^^^^^^

The Docker image ships with the **Sigma Core** rules bundled at ``/app/sigma`` (set via the ``SIGMA_RULES_PATH`` environment variable). To use your own rules directory instead, mount it as a volume and pass it with ``-r``:

.. code-block:: bash

   # Linux / macOS
   docker run --rm \
     -v "$(pwd)/data:/app/data" \
     -v "$(pwd)/my_sigma_rules:/app/custom_sigma" \
     recongraph -f forensic_timeline.csv -r /app/custom_sigma

   # Windows (PowerShell)
   docker run --rm `
     -v "${PWD}\data:/app/data" `
     -v "${PWD}\my_sigma_rules:/app/custom_sigma" `
     recongraph -f forensic_timeline.csv -r /app/custom_sigma

.. note::

   The bundled Sigma Core rules path (``/app/sigma``) is exported as the ``SIGMA_RULES_PATH``
   environment variable inside the container. ReconGraph can use this as a default when ``-r`` is not specified.

Library Usage
-------------

You can integrate ReconGraph into your own forensic analysis scripts using the unified facade.

.. code-block:: python
 
    from recongraph import ReconGraph
 
    # Initialize the pipeline
    pipeline = ReconGraph(
        input_file='forensic_timeline.csv', 
        rules_dir='rules/'
    )

   # The library takes one path per file; each output except graph_output is written only when its path is given
   pipeline.run_all(
       graph_output='analysis_graph.graphml',
       temporal_output='analysis_temporal.graphml',
       metadata_output='analysis_meta.json',
       csv_output='event_details.csv',
       sigma_output='labeled_source.csv'
   )

Reconstructing Paths Between Events
-----------------------------------

``python -m recongraph.reconstruct`` lists the paths from a source event ``s`` to a destination event ``d`` with at
most ``k`` edges (``--max-len``, default 8) in a graph written by ``recongraph``:

*   ``dfs``: simple paths in the aggregate graph (``networkx.all_simple_paths``); no node repeats and time is ignored.
*   ``time``: time-respecting walks ``e1..em`` over the temporal graph: ``e1`` leaves ``s``, ``em`` arrives at ``d``,
    ``t_dst(e_i) <= t_src(e_i+1)`` and, with ``--max-gap W``, ``t_src(e_i+1) - t_dst(e_i) <= W``. Nodes may repeat, a
    transition is used at most once, and transitions without timestamps are skipped.
*   ``replay``: consecutive transitions (``seq(e_i+1) = seq(e_i) + 1``), i.e. the order the log shows.
*   ``compare``: all three. A DFS path is *feasible* when some time-respecting walk visits the same node sequence,
    otherwise *temporally impossible*; the share of impossible DFS paths is reported.

.. code-block:: bash

   python -m recongraph.reconstruct --temporal result/recongraph_temporal.graphml --agg result/recongraph_agg.graphml \
       --src "Base64 Encoded PowerShell" --dst "Malware Callback" --mode compare --max-len 8 --max-gap 60s --out paths.json

``--src``/``--dst`` accept a node id, an exact label or a unique label substring. ``--cap`` limits the number of
paths per method and sets ``truncated`` when reached. The functions (``dfs_paths``, ``time_respecting_paths``,
``replay_paths``, ``compare``) also accept graphs loaded from an ``EdgeGraph`` via ``load_graphs(edge_graph)``.
Neo4j equivalents (import with ``apoc.import.graphml`` and ``{readLabels: true, storeNodeIds: true, defaultRelationshipType: 'NEXT'}``)
are in ``docs/cypher/``. Both work in both node modes; with ``--node=drain`` a label is an event identity such as
``Microsoft-Windows-Sysmon:1``. ``window_around_sigma.cypher`` anchors on annotated rows (``src_level``/``dst_level`` on the
temporal edges with ``--node=drain``, the node's ``level`` with ``--node=sigma``).

Running Tests
-------------

To ensure that the installation is correct and the code is functioning as expected, you can run the test suite provided in the ``tests/`` directory.

1.  **Install Test Dependencies**:
    Ensure you have ``pytest`` installed.

    .. code-block:: bash

       pip install pytest pandas pyyaml

2.  **Run Tests**:
    Navigate to the project root directory and execute:

    .. code-block:: bash

       pytest tests/

    You should see output indicating that all tests have passed.
