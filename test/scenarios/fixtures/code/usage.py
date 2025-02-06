import pandas as pd
from flask import Flask, request

app = Flask(__name__)
df = pd.DataFrame({'A': [1, 2], 'B': [3, 4]})
