import os
from pathlib import Path

REPO = Path(__file__).parents[1]
SIGMA_RULES = Path(os.environ.get("SIGMA_RULES_PATH") or REPO.parent / "sigma" / "rules")
SIGMA = SIGMA_RULES.parent
