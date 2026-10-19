import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from recongraph.recongraph import SigmaLabel

REPO = Path(__file__).parents[1]
SIGMA_RULES = Path(os.environ.get("SIGMA_RULES_PATH") or REPO.parent / "sigma" / "rules")
SIGMA = SIGMA_RULES.parent
SAMPLE_CSV_CONFIGS = [(csv, flexible)
                      for csv in ("1/failed-login.csv", "2/windows-firewall-disabled-evtx.csv", "3/4616-with-regex.csv")
                      for flexible in (True, False)]


def _label(config):
    csv, flexible = config
    return SigmaLabel(str(REPO / "dataset" / csv), str(SIGMA_RULES), flexible_mode=flexible).run()


@pytest.fixture(scope="session")
def labeled_sample_csvs():
    """dataset/1-3 CSVs labeled with the full sigma rules (~5 min), shared by the regression tests."""
    if not SIGMA_RULES.exists():
        pytest.skip("sigma rules not found next to recongraph")
    with ProcessPoolExecutor() as pool:
        return dict(zip(SAMPLE_CSV_CONFIGS, pool.map(_label, SAMPLE_CSV_CONFIGS)))
