import litellm
from litellm import completion
import torch
import tensorflow as tf
import keras
import jax.numpy as jnp
from sklearn.linear_model import LogisticRegression
from transformers import pipeline, AutoTokenizer
from sentence_transformers import SentenceTransformer
import tiktoken
from tokenizers import Tokenizer
from vllm import LLM, SamplingParams
from llama_cpp import Llama
import onnxruntime as ort
import dspy
from autogen_agentchat.agents import AssistantAgent
import instructor
import vertexai
from vertexai.generative_models import GenerativeModel
import google.generativeai as legacy_genai
import replicate
import chromadb
from pinecone import Pinecone
from qdrant_client import QdrantClient
import weaviate
from pymilvus import MilvusClient
import faiss
from pgvector.sqlalchemy import Vector
from mem0 import Memory
from langfuse import Langfuse


def run(messages, docs):
    completion(model="gpt-4o", messages=messages)
    litellm.embedding(model="text-embedding-3-small", input=docs)
    torch.nn.Linear(4, 2)
    tf.keras.Sequential()
    keras.layers.Dense(8)
    jnp.zeros(3)
    LogisticRegression().fit(docs, docs)
    pipeline("sentiment-analysis")
    AutoTokenizer.from_pretrained("bert-base-uncased")
    SentenceTransformer("all-MiniLM-L6-v2").encode(docs)
    tiktoken.get_encoding("cl100k_base")
    Tokenizer.from_pretrained("bert-base-uncased")
    LLM(model="facebook/opt-125m").generate(docs, SamplingParams())
    Llama(model_path="model.gguf")
    ort.InferenceSession("model.onnx")
    dspy.configure(lm=dspy.LM("openai/gpt-4o-mini"))
    AssistantAgent("assistant", model_client=None)
    instructor.from_provider("openai/gpt-4o")
    vertexai.init(project="p")
    GenerativeModel("gemini-1.5-pro")
    legacy_genai.GenerativeModel("gemini-pro")
    replicate.run("meta/llama-3-70b", input={})
    chromadb.PersistentClient(path="db")
    Pinecone(api_key="k").Index("docs")
    QdrantClient(url="http://localhost:6333")
    weaviate.connect_to_local()
    MilvusClient("milvus.db")
    faiss.IndexFlatL2(128)
    Vector(3)
    Memory()
    Langfuse()
