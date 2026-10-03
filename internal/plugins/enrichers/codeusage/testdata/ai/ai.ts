import { pipeline } from "@huggingface/transformers";
import { pipeline as xpipeline } from "@xenova/transformers";
import * as tf from "@tensorflow/tfjs";
import * as ort from "onnxruntime-node";
import { Pinecone } from "@pinecone-database/pinecone";
import { ChromaClient } from "chromadb";
import { QdrantClient } from "@qdrant/js-client-rest";
import weaviate from "weaviate-client";
import Replicate from "replicate";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { VertexAI } from "@google-cloud/vertexai";
import { encoding_for_model } from "tiktoken";
import { getEncoding } from "js-tiktoken";
import { getLlama } from "node-llama-cpp";
import { genkit } from "genkit";
import { googleAI } from "@genkit-ai/google-genai";
import { Agent } from "@openai/agents";
import { Langfuse } from "langfuse";

export async function run() {
  await pipeline("sentiment-analysis");
  await xpipeline("feature-extraction");
  tf.sequential();
  await ort.InferenceSession.create("model.onnx");
  new Pinecone().index("docs");
  new ChromaClient();
  new QdrantClient({ url: "http://localhost:6333" });
  await weaviate.connectToLocal();
  await new Replicate().run("meta/llama-3-70b", { input: {} });
  new GoogleGenerativeAI("key").getGenerativeModel({ model: "gemini-pro" });
  new VertexAI({ project: "p" });
  encoding_for_model("gpt-4o");
  getEncoding("cl100k_base");
  await getLlama();
  genkit({ plugins: [googleAI()] });
  new Langfuse();
  return Agent;
}
