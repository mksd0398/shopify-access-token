"""Run: python test_get_access_token.py"""
import hashlib
import hmac
import tempfile
from pathlib import Path

import get_access_token as g

# HMAC: valid signature passes, tampered param fails.
secret = "shh"
params = {"code": ["abc"], "shop": ["x.myshopify.com"], "state": ["s"], "timestamp": ["1"]}
msg = "code=abc&shop=x.myshopify.com&state=s&timestamp=1"
params["hmac"] = [hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()]
assert g.valid_hmac(params, secret)
assert not g.valid_hmac({**params, "code": ["evil"]}, secret)

# update_env: replaces in place, appends new, keeps comments.
p = Path(tempfile.mkdtemp()) / ".env"
p.write_text("# c\nSHOPIFY_ACCESS_TOKEN=old\nOTHER=1", encoding="utf-8")
g.update_env({"SHOPIFY_ACCESS_TOKEN": "new", "SHOPIFY_STORE": "x.myshopify.com"}, p)
assert p.read_text(encoding="utf-8") == (
    "# c\nSHOPIFY_ACCESS_TOKEN=new\nOTHER=1\nSHOPIFY_STORE=x.myshopify.com\n"
)

# environments: picks up non-empty SHOPIFY_STORE_<NAME> only.
assert g.environments({"SHOPIFY_STORE_PROD": "a.myshopify.com", "SHOPIFY_STORE_STAGE": "",
                       "SHOPIFY_STORE": "a.myshopify.com"}) == {"PROD": "a.myshopify.com"}

assert g.normalize_shop("https://My-Store.myshopify.com/admin") == "my-store.myshopify.com"
print("ok")
