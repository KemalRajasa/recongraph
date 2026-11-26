Examples & Sample Datasets
==========================

This page walks through the sample datasets in the ``dataset/`` folder of the repository: from the original log, to a
Plaso timeline, to the ReconGraph graphs, to the visualizer.

Each sample lives in its own folder:

.. code-block:: text

   dataset/<sample>/
   ├── README.md                 # source, license, how the files were made, node and edge counts
   ├── <name>.evtx               # original log (Windows samples only)
   ├── <name>.jsonl.xz           # Plaso timeline, psort -o json_line
   ├── <name>.csv.xz             # Plaso timeline, psort -o dynamic
   ├── recongraph-drain/         # ReconGraph output, --node drain
   │   ├── recongraph_agg.graphml.xz
   │   ├── recongraph_temporal.graphml.xz
   │   └── recongraph_meta.json
   └── recongraph-sigma/         # ReconGraph output, --node sigma

The Sample Datasets
-------------------

.. list-table::
   :header-rows: 1
   :widths: 22 38 10 10 10 10

   * - Folder
     - Source (scenario)
     - Drain nodes
     - Drain edges
     - Sigma nodes
     - Sigma edges
   * - ``windows_sideload``
     - EVTX-ATTACK-SAMPLES: DLL side-loading, UAC bypass, rundll32 injection, C2
     - 4
     - 8
     - 8
     - 12
   * - ``windows_psexec``
     - EVTX-ATTACK-SAMPLES: PsExec over SMB, Meterpreter
     - 5
     - 8
     - 3
     - 3
   * - ``linux_cam-lds``
     - CAM-LDS: web server compromise, sudo to root, SSH key; full timeline
     - 596
     - 2,622
     - 27
     - 97
   * - ``linux_cam-lds`` (window)
     - the same, attack window 08:58–09:23 UTC
     - 129
     - 381
     - 17
     - 40

Edges are those of the aggregate graph (``recongraph_agg.graphml``). The sources and licenses are in
:doc:`license`, and the rule versions in ``dataset/README.md``.

Prerequisites
-------------

* ReconGraph installed — see :doc:`installation`.
* ``xz`` to extract the files (on Windows, 7-Zip).
* The Sigma rules of the sample — see ``dataset/README.md``. The Windows samples use a clone of
  `hayabusa-rules <https://github.com/Yamato-Security/hayabusa-rules>`_; the Linux sample uses ``rules/linux`` and
  ``rules/web`` of `SigmaHQ <https://github.com/SigmaHQ/sigma>`_, copied into one folder because ``-r`` takes one folder.
  In the examples below these are ``/path/to/hayabusa-rules`` and ``/path/to/sigma-linux-web``.
* Docker, only to make a timeline from the original log yourself (Step 2).

Reproducing a Sample
--------------------

The steps are the same for every sample. Sample ``windows_psexec`` is used as the example.

Step 1 — Extract the files
^^^^^^^^^^^^^^^^^^^^^^^^^^

ReconGraph and the visualizer read uncompressed files. ``-k`` keeps the ``.xz`` files:

.. code-block:: bash

   xz -dk dataset/windows_psexec/*.xz dataset/windows_psexec/*/*.xz

Step 2 (optional) — Make the timeline from the original log
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The extracted ``psexec.jsonl`` is ready to use. To make it yourself from ``psexec.evtx`` with Plaso:

.. code-block:: bash

   cd dataset/windows_psexec
   docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 \
     log2timeline.py --unattended --parsers winevtx --storage-file /data/psexec.plaso /data/psexec.evtx
   docker run --rm -v "$(pwd):/data" log2timeline/plaso:20261027 \
     psort.py -o json_line -w /data/psexec.jsonl /data/psexec.plaso

With the same Plaso version the result is identical to the extracted file. The ``README.md`` of the Linux sample
gives its Plaso commands.

Step 3 — Generate the graphs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run ReconGraph on the timeline. ``-o`` names an output folder, which must not hold an earlier run:

.. code-block:: bash

   recongraph \
     -f dataset/windows_psexec/psexec.jsonl \
     -r /path/to/hayabusa-rules/sigma \
     --exclude-status deprecated,unsupported \
     --exclude-rules-file /path/to/hayabusa-rules/config/exclude_rules.txt \
     --node drain \
     -o result/psexec-drain

Run it again with ``--node sigma -o result/psexec-sigma`` for the Sigma label graph. With the same rule version,
``recongraph_agg.graphml`` and ``recongraph_temporal.graphml`` are identical to the extracted ones in
``dataset/windows_psexec/recongraph-drain/`` and ``recongraph-sigma/``.

For the Linux sample, use the SigmaHQ rules and ``--strict``:

.. code-block:: bash

   recongraph \
     -f dataset/linux_cam-lds/videoserver_window.jsonl \
     -r /path/to/sigma-linux-web \
     --strict \
     --node drain \
     -o result/cam-lds-window-drain

Step 4 — Open the visualizer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Open ``recongraph/visualizer.html`` in any modern web browser (no server or build step required). Click
**Load GraphML** (or drag the file onto the page) and select ``recongraph_agg.graphml`` from Step 3, or the extracted
one of the sample. The graph renders with severity-colored nodes, layout controls, a severity filter, and a node
inspector.

With the graph loaded, use the header buttons:

* **Export SVG** — saves a standalone vector image of the current graph.
* **Export JSON** — saves a simplified ``{ nodes, edges }`` structure
  (id, label, level, count, timestamp, and edge weights).

Advanced: Strict Mode
---------------------

By default ReconGraph runs in **flexible** matching mode, which searches broadly
across log fields. The ``--strict`` flag enables logsource validation, which only
applies rules whose logsource matches the detected log type. Compare the two on
the attack window of the Linux sample:

.. code-block:: bash

   recongraph -f dataset/linux_cam-lds/videoserver_window.jsonl -r /path/to/sigma-linux-web \
     --node sigma -o result/cam-lds-window-sigma-flexible
   recongraph -f dataset/linux_cam-lds/videoserver_window.jsonl -r /path/to/sigma-linux-web \
     --node sigma --strict -o result/cam-lds-window-sigma-strict

.. list-table::
   :header-rows: 1
   :widths: 24 14 14 18

   * - Mode
     - Nodes
     - Edges
     - Labeled rows
   * - Flexible (default)
     - 19
     - 50
     - 32,867
   * - Strict (``--strict``)
     - 17
     - 40
     - 32,851

.. note::

   Strict mode is a **graph-size / complexity reducer**, not an accuracy fix.
   On Plaso *super-timelines* (which interleave NTFS USN journal, Prefetch,
   registry, and event-log rows) both modes still produce false positives — a
   generic rule can match unrelated filesystem-journal text. Strict mode mainly
   reduces the *variety* of matched rules (via logsource gating); it does not
   eliminate the noise. Treat the labeled events as leads to verify, not
   conclusions.

Interpreting the Graph
----------------------

* **Node size** scales with how many log lines matched that event.
* **Node color** encodes Sigma severity (critical, high, medium, low,
  informational).
* **Edge thickness / weight** encodes how often that transition occurred.
* A large **self-loop** or a node connected to almost everything usually
  indicates an over-matching (frequently false-positive) rule rather than a
  meaningful attacker pivot — a signal to narrow your rule set or pre-filter the
  input timeline.
