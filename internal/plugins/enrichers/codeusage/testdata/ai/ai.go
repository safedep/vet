package main

import (
	"context"

	"github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/compose"
	"github.com/firebase/genkit/go/genkit"
	"github.com/pkoukk/tiktoken-go"
	"github.com/qdrant/go-client/qdrant"
	"github.com/pinecone-io/go-pinecone/v4/pinecone"
	"github.com/milvus-io/milvus/client/v2/milvusclient"
	"github.com/weaviate/weaviate-go-client/v5/weaviate"
	"github.com/pgvector/pgvector-go"
	chroma "github.com/amikos-tech/chroma-go/pkg/api/v2"
	ort "github.com/yalue/onnxruntime_go"
	"gorgonia.org/gorgonia"
	"github.com/anthropics/anthropic-sdk-go"
	oai "github.com/openai/openai-go/v2"
)

func main() {
	ctx := context.Background()
	_, _ = openai.NewChatModel(ctx, nil)
	_ = compose.NewChain[string, string]()
	_ = genkit.Init(ctx)
	_, _ = tiktoken.GetEncoding("cl100k_base")
	_, _ = qdrant.NewClient(nil)
	_, _ = pinecone.NewClient(pinecone.NewClientParams{})
	_, _ = milvusclient.New(ctx, nil)
	_, _ = weaviate.NewClient(weaviate.Config{})
	_ = pgvector.NewVector(nil)
	_, _ = chroma.NewHTTPClient()
	_ = ort.InitializeEnvironment()
	_ = gorgonia.NewGraph()
	_ = anthropic.NewClient()
	_ = oai.NewClient()
}
