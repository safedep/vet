//go:build cgo

package codeusage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAISignatures runs the AI signatures on programs that call popular AI
// libraries the way their documentation does, and on programs with names
// that only look like those of an AI library. The matched signatures must
// be exactly the expected ones.
func TestAISignatures(t *testing.T) {
	cases := map[string][]string{
		"ai.py": {
			"ai.autogen", "ai.chroma", "ai.dspy", "ai.faiss", "ai.huggingface.tokenizers", "ai.huggingface.transformers",
			"ai.instructor", "ai.jax", "ai.langfuse", "ai.litellm", "ai.llamacpp", "ai.mem0", "ai.milvus", "ai.onnxruntime",
			"ai.pgvector", "ai.pinecone", "ai.pytorch", "ai.qdrant", "ai.replicate", "ai.sentence_transformers", "ai.sklearn",
			"ai.tensorflow", "ai.tiktoken", "ai.vertexai", "ai.vllm", "ai.weaviate", "google.genai.client",
		},
		"ai.ts": {
			"ai.chroma", "ai.elevenlabs", "ai.genkit", "ai.huggingface.transformers", "ai.langfuse", "ai.llamacpp",
			"ai.onnxruntime", "ai.pinecone", "ai.qdrant", "ai.replicate", "ai.tensorflow", "ai.tiktoken", "ai.vertexai",
			"ai.weaviate", "google.genai.client", "langchain.js",
		},
		"Ai.java": {
			"ai.djl", "ai.dl4j", "ai.milvus", "ai.onnxruntime", "ai.pinecone", "ai.qdrant", "ai.smile", "ai.tensorflow",
			"ai.tiktoken", "ai.tribuo", "ai.vertexai", "ai.weaviate", "anthropic.client", "langchain.chat_models",
		},
		"ai.go": {
			"ai.chroma", "ai.eino", "ai.genkit", "ai.gorgonia", "ai.milvus", "ai.onnxruntime", "ai.pgvector", "ai.pinecone",
			"ai.qdrant", "ai.tiktoken", "ai.weaviate", "anthropic.client", "anthropic.messages", "openai.client",
		},
		"Ai.cs": {
			"ai.llamacpp", "ai.mlnet", "ai.onnxruntime", "ai.pinecone", "ai.pytorch", "ai.qdrant", "ai.tiktoken",
			"ai.vertexai", "azure.ai.foundry", "google.genai.client",
		},
		"ai.rs": {
			"ai.burn", "ai.candle", "ai.fastembed", "ai.genai_rs", "ai.huggingface.hub", "ai.huggingface.tokenizers",
			"ai.lancedb", "ai.linfa", "ai.llamacpp", "ai.mistralrs", "ai.onnxruntime", "ai.pytorch", "ai.qdrant", "ai.rig",
			"ai.tiktoken",
		},
		"ai.php": {
			"ai.huggingface.transformers", "ai.llphant", "ai.neuron", "ai.phpml", "ai.prism", "ai.rubixml", "ai.symfony",
			"ai.tiktoken", "google.genai.client",
		},
		"ai.rb": {
			"ai.dspy", "ai.huggingface.transformers", "ai.omniai", "ai.onnxruntime", "ai.pytorch", "ai.qdrant",
			"ai.ruby_llm", "ai.rumale", "ai.tiktoken", "google.genai.client",
		},
		"Onnx.cs":    {"ai.onnxruntime"},
		"plain.py":   nil,
		"plain.ts":   nil,
		"Plain.java": nil,
	}
	for file, want := range cases {
		t.Run(file, func(t *testing.T) {
			got := fixtureMatches(t, "ai", file, "ai")
			assert.Empty(t, missing(want, got), "signatures that do not match")
			assert.Empty(t, missing(got, want), "signatures that match and should not")
		})
	}
}
