import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

# Built at runtime so no Stripe-format literal is ever committed (GitHub push protection
# rightly blocks those). The scanner sees a realistic key in the materialized fixture.
FAKE_STRIPE = "sk_" + "live_" + "51HxT2cAbCdEfGhIjKlMnOpQr"
FIXTURE_SRC = Path(__file__).parent / "fixtures" / "vulnerable_app"


@pytest.fixture
def vulnerable_app(tmp_path) -> Path:
    dest = tmp_path / "vulnerable_app"
    shutil.copytree(FIXTURE_SRC, dest)
    js = dest / "server.js"
    js.write_text(js.read_text().replace("__FAKE_STRIPE_KEY__", FAKE_STRIPE))
    return dest
