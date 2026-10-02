package reputation

import "github.com/safedep/vet/v2/model"

// popular holds well-known package names of each ecosystem, the targets of
// a typosquat.
//
// gap G7: Insights v2 has no corpus of popular package names. This short
// list covers the most downloaded packages only, so the typosquat control
// misses squats of other packages.
var popular = map[model.Ecosystem][]string{
	model.EcosystemNpm: {
		"react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "moment",
		"request", "typescript", "webpack", "babel-core", "@babel/core", "eslint", "prettier", "jest",
		"mocha", "chai", "vue", "angular", "next", "nuxt", "svelte", "jquery", "underscore", "async",
		"bluebird", "uuid", "dotenv", "cors", "body-parser", "cookie-parser", "jsonwebtoken", "bcrypt",
		"mongoose", "mongodb", "mysql", "mysql2", "pg", "redis", "ioredis", "sequelize", "knex",
		"socket.io", "ws", "yargs", "minimist", "glob", "rimraf", "mkdirp", "fs-extra", "semver",
		"inquirer", "ora", "colors", "classnames", "prop-types", "styled-components", "tailwindcss",
		"postcss", "autoprefixer", "sass", "less", "rollup", "vite", "esbuild", "parcel", "nodemon",
		"ts-node", "tslib", "rxjs", "zone.js", "core-js", "regenerator-runtime", "date-fns", "dayjs",
		"luxon", "ramda", "immutable", "redux", "react-redux", "mobx", "zustand", "graphql",
		"apollo-server", "@apollo/client", "node-fetch", "cross-env", "cross-spawn", "chokidar",
		"electron", "puppeteer", "playwright", "cheerio", "jsdom", "sharp", "multer", "passport",
		"helmet", "morgan", "winston", "pino", "bunyan", "joi", "yup", "zod", "ajv", "validator",
		"qs", "superagent", "got", "ky", "nanoid", "shortid", "crypto-js", "bignumber.js", "big.js",
		"handlebars", "ejs", "pug", "marked", "highlight.js", "js-yaml", "xml2js", "fast-xml-parser",
		"discord.js", "twilio", "stripe", "aws-sdk", "firebase", "@angular/core",
		"@types/node", "@types/react", "eslint-plugin-react", "husky", "lint-staged", "concurrently",
	},
	model.EcosystemPyPI: {
		"requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn",
		"tensorflow", "torch", "keras", "django", "flask", "fastapi", "uvicorn", "gunicorn", "celery",
		"redis", "sqlalchemy", "psycopg2", "psycopg2-binary", "pymysql", "pymongo", "boto3", "botocore",
		"awscli", "s3transfer", "setuptools", "wheel", "pip", "six", "certifi", "idna", "chardet",
		"charset-normalizer", "python-dateutil", "pytz", "tzdata", "pyyaml", "jinja2", "markupsafe",
		"click", "attrs", "packaging", "pyparsing", "cryptography", "pyopenssl", "cffi", "pycparser",
		"rsa", "pyasn1", "jmespath", "docutils", "colorama", "tqdm", "pillow", "beautifulsoup4", "lxml",
		"html5lib", "selenium", "scrapy", "pytest", "pytest-cov", "coverage", "mock", "tox", "black",
		"flake8", "pylint", "mypy", "isort", "autopep8", "requests-oauthlib", "oauthlib", "pyjwt",
		"paramiko", "fabric", "ansible", "pydantic", "typing-extensions", "aiohttp", "httpx", "httpcore",
		"anyio", "sniffio", "h11", "websockets", "grpcio", "protobuf", "google-auth", "google-api-core",
		"openai", "anthropic", "langchain", "transformers", "huggingface-hub", "tokenizers", "datasets",
		"opencv-python", "pyarrow", "polars", "xgboost", "lightgbm", "catboost", "nltk", "spacy",
		"gensim", "networkx", "sympy", "statsmodels", "plotly", "dash", "streamlit", "gradio", "jupyter",
		"notebook", "ipython", "ipykernel", "virtualenv", "pipenv", "poetry", "filelock", "platformdirs",
		"distlib", "toml", "tomli", "wrapt", "decorator", "simplejson", "ujson", "orjson", "msgpack",
		"marshmallow", "werkzeug", "itsdangerous", "pyserial", "pexpect", "psutil", "docker", "kubernetes",
	},
}

// aiSDKs are the packages that give a project an AI capability: an LLM
// provider, an agent framework, or an MCP library.
var aiSDKs = map[model.Ecosystem][]string{
	model.EcosystemNpm: {
		"openai", "@anthropic-ai/sdk", "@anthropic-ai/claude-agent-sdk", "@google/generative-ai", "@google/genai",
		"@mistralai/mistralai", "cohere-ai", "groq-sdk", "ollama", "replicate", "@huggingface/inference",
		"ai", "@ai-sdk/openai", "@ai-sdk/anthropic", "langchain", "@langchain/core", "@langchain/openai",
		"llamaindex", "@modelcontextprotocol/sdk", "@aws-sdk/client-bedrock-runtime", "@azure/openai",
	},
	model.EcosystemPyPI: {
		"openai", "anthropic", "claude-agent-sdk", "google-generativeai", "google-genai", "mistralai",
		"cohere", "groq", "ollama", "replicate", "huggingface-hub", "transformers", "langchain",
		"langchain-core", "langchain-openai", "langgraph", "llama-index", "crewai", "autogen", "pyautogen",
		"mcp", "fastmcp", "litellm", "vllm", "instructor", "dspy-ai", "semantic-kernel",
	},
	model.EcosystemGo: {
		"github.com/openai/openai-go", "github.com/anthropics/anthropic-sdk-go", "github.com/sashabaranov/go-openai",
		"github.com/tmc/langchaingo", "github.com/mark3labs/mcp-go", "github.com/modelcontextprotocol/go-sdk",
		"google.golang.org/genai", "github.com/google/generative-ai-go",
	},
}
