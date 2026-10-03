//go:build cgo

package codeusage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignaturesMatchSDKCode runs the embedded signatures on short programs
// that call each SDK the way its documentation does.
func TestSignaturesMatchSDKCode(t *testing.T) {
	cases := []struct {
		file string
		code string
		want []string
	}{
		{"chat.cs", "using OpenAI.Chat;\n\nvar client = new ChatClient(\"gpt-4o\", key);\nvar reply = client.CompleteChat(\"hi\");\n", []string{"openai.client"}},
		{"azure.cs", "using Azure.AI.OpenAI;\n\nvar client = new AzureOpenAIClient(endpoint, credential);\n", []string{"openai.azure"}},
		{"claude.cs", "using Anthropic;\n\nvar client = new AnthropicClient();\n", []string{"anthropic.client"}},
		{"kernel.cs", "using Microsoft.SemanticKernel;\n\nvar kernel = Kernel.CreateBuilder().AddOpenAIChatCompletion(\"gpt-4o\", key).Build();\n", []string{"microsoft.semantickernel.core"}},
		{"meai.cs", "using Microsoft.Extensions.AI;\n\nIChatClient client = inner.AsBuilder().UseFunctionInvocation().Build();\n", []string{"microsoft.extensions.ai"}},
		{"mcp.cs", "using ModelContextProtocol.Server;\n\nbuilder.Services.AddMcpServer().WithStdioServerTransport();\n", []string{"mcp.sdk.server"}},
		{"main.rs", "use async_openai::Client;\n\nasync fn run() {\n    let client = Client::new();\n    let r = client.chat().create(req).await;\n}\n", []string{"openai.client"}},
		{"bedrock.rs", "async fn run(config: &SdkConfig) {\n    let client = aws_sdk_bedrockruntime::Client::new(config);\n}\n", []string{"aws.bedrock.runtime"}},
		{"server.rs", "use rmcp::ServiceExt;\n\nasync fn run() {\n    let service = Counter::new().serve(rmcp::transport::stdio()).await;\n}\n", []string{"mcp.sdk.server"}},
		{"chat.php", "<?php\n\n$client = OpenAI::client(getenv('OPENAI_API_KEY'));\n$result = $client->chat()->create(['model' => 'gpt-4o']);\n", []string{"openai.client"}},
		{"claude.php", "<?php\nuse Anthropic;\n\n$client = Anthropic::client(getenv('ANTHROPIC_API_KEY'));\n", []string{"anthropic.client"}},
		{"bedrock.php", "<?php\nuse Aws\\BedrockRuntime\\BedrockRuntimeClient;\n\n$client = new BedrockRuntimeClient(['region' => 'us-east-1']);\n", []string{"aws.bedrock.runtime"}},
		{"chat.rb", "require 'openai'\n\nclient = OpenAI::Client.new(access_token: ENV['OPENAI_API_KEY'])\nclient.chat(parameters: { model: 'gpt-4o' })\n", []string{"openai.client"}},
		{"claude.rb", "require 'anthropic'\n\nclient = Anthropic::Client.new\nclient.messages.create(model: 'claude-sonnet-4-5', max_tokens: 64, messages: [])\n", []string{"anthropic.client"}},
		{"assistant.rb", "require 'langchain'\n\nllm = Langchain::LLM::OpenAI.new(api_key: ENV['OPENAI_API_KEY'])\nassistant = Langchain::Assistant.new(llm: llm)\n", []string{"langchain.chat_models", "langchain.agents"}},
		{"server.rb", "require 'mcp'\n\nserver = MCP::Server.new(name: 'demo')\n", []string{"mcp.sdk.server"}},
		{"openai.go", "package main\n\nimport openai \"github.com/sashabaranov/go-openai\"\n\nfunc main() {\n\tclient := openai.NewClient(\"key\")\n\t_ = client\n}\n", []string{"openai.client"}},
		{"ollama.go", "package main\n\nimport \"github.com/ollama/ollama/api\"\n\nfunc main() {\n\tclient, _ := api.ClientFromEnvironment()\n\t_ = client\n}\n", []string{"ollama.client"}},
		{"llm.go", "package main\n\nimport \"github.com/tmc/langchaingo/llms/openai\"\n\nfunc main() {\n\tllm, _ := openai.New()\n\t_ = llm\n}\n", []string{"langchain.chat_models"}},
		{"genai.go", "package main\n\nimport \"google.golang.org/genai\"\n\nfunc main() {\n\tclient, _ := genai.NewClient(ctx, nil)\n\t_ = client\n}\n", []string{"google.genai.client"}},
		{"mcp.go", "package main\n\nimport \"github.com/modelcontextprotocol/go-sdk/mcp\"\n\nfunc main() {\n\tserver := mcp.NewServer(&mcp.Implementation{Name: \"demo\"}, nil)\n\t_ = server\n}\n", []string{"mcp.sdk.server"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, tc.file, tc.code)
			a, err := defaultAnalyzer(context.Background(), dir)
			require.NoError(t, err)
			got := map[string]bool{}
			for _, m := range a.Matches {
				got[m.Signature.ID] = true
			}
			for _, id := range tc.want {
				assert.True(t, got[id], "%s does not match %s, got %v", tc.file, id, got)
			}
		})
	}
}

// TestSignaturesIgnorePlainCode checks that code with no AI SDK matches no
// AI signature, also when its names look like those of an SDK.
func TestSignaturesIgnorePlainCode(t *testing.T) {
	cases := map[string]string{
		"app.cs":  "using System.Net.Http;\nusing MyCompany.Chat;\n\nvar http = new HttpClient();\nvar chat = new ChatClient();\nchat.CompleteChat(\"hi\");\n",
		"main.rs": "use reqwest::Client;\n\nasync fn run() {\n    let client = Client::new();\n    client.get(\"https://example.com\").send().await;\n}\n",
		"app.php": "<?php\nuse GuzzleHttp\\Client;\n\n$client = new Client();\n$client->get('/');\n",
		"app.rb":  "require 'net/http'\n\nclient = Net::HTTP.new('example.com')\nclient.get('/')\n",
		"main.go": "package main\n\nimport \"net/http\"\n\nfunc main() {\n\tclient := http.Client{}\n\t_, _ = client.Get(\"https://example.com\")\n}\n",
	}
	for file, code := range cases {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, file, code)
			a, err := defaultAnalyzer(context.Background(), dir)
			require.NoError(t, err)
			for _, m := range a.Matches {
				assert.NotContains(t, m.Signature.Tags, "ai", "%s matches %s", file, m.Signature.ID)
			}
		})
	}
}

func TestDynamoDBNeedsItsService(t *testing.T) {
	cases := map[string]bool{
		"import boto3\n\ntable = boto3.resource('dynamodb').Table('t')\n": true,
		"import boto3\n\nclient = boto3.client(\"dynamodb\")\n":           true,
		"import boto3\n\ns3 = boto3.client('s3')\n":                       false,
	}
	for code, want := range cases {
		dir := t.TempDir()
		write(t, dir, "app.py", code)
		a, err := defaultAnalyzer(context.Background(), dir)
		require.NoError(t, err)
		got := false
		for _, m := range a.Matches {
			got = got || m.Signature.ID == "python.database.dynamodb"
		}
		assert.Equal(t, want, got, code)
	}
}
