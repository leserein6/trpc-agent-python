from pathlib import Path
import sys

ROOT = Path(
    __file__).resolve().parents[3] / "examples" / "skills_code_review_agent"
sys.path.insert(0, str(ROOT))
