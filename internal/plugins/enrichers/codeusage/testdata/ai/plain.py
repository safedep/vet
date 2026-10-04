import json
from collections import Counter
from app.models import Pipeline, Tokenizer
from app import torch_utils

Pipeline().run()
Tokenizer().encode("text")
torch_utils.load()
Counter(json.loads("[]"))
