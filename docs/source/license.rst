Licenses
========

ReconGraph License
------------------

This project is licensed under the **MIT License**.

.. literalinclude:: ../../LICENSE
   :language: text

Sigma Rules License
-------------------

ReconGraph utilizes **Sigma rules** for event detection. These rules are not distributed with this package and must be downloaded separately.

*   The **Sigma specification** is public domain.
*   The **Sigma rules** (from the `SigmaHQ repository <https://github.com/SigmaHQ/sigma>`_) are typically released under the **Detection Rule License (DRL) 1.1**.

Detection Rule License (DRL) 1.1
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Dependencies and external rule sets may be subject to their own license terms. Please review the license file included with any downloaded Sigma rules.

Sample Datasets License
-----------------------

The sample datasets in the ``dataset/`` folder of the repository keep the license of their source. That license applies to every
file in the sample's folder, including the timelines and graphs derived from the source:

*   ``dataset/windows_sideload/`` and ``dataset/windows_psexec/``: from `EVTX-ATTACK-SAMPLES <https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>`_
    by sbousseaden, licensed under the **GNU General Public License v3.0** (copy in each folder as ``LICENSE.GPL``).
*   ``dataset/linux_cam-lds/``: from M. Landauer, W. Hotwagner, T. Boenke, F. Skopik, M. Wurzenberger, *Cyber Attack
    Manifestations - Log Data Set (CAM-LDS)*, Zenodo, 2026, `doi:10.5281/zenodo.18861762 <https://doi.org/10.5281/zenodo.18861762>`_,
    licensed under **CC-BY-4.0**.

Each sample's ``README.md`` describes how its files were derived from the source.
