using Microsoft.ML;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.Tokenizers;
using Azure.AI.Inference;
using Azure.AI.Projects;
using LLama;
using LLama.Common;
using TorchSharp;
using Qdrant.Client;
using Pinecone;
using Google.Cloud.AIPlatform.V1;
using Mscc.GenerativeAI;

class Ai
{
    void Run()
    {
        var ml = new MLContext();
        var session = new InferenceSession("model.onnx");
        var tokenizer = TiktokenTokenizer.CreateForModel("gpt-4o");
        var chat = new ChatCompletionsClient(endpoint, credential);
        var project = new AIProjectClient(endpoint, credential);
        var weights = LLamaWeights.LoadFromFile(new ModelParams("model.gguf"));
        var t = torch.zeros(3);
        var qdrant = new QdrantClient("localhost");
        var pinecone = new PineconeClient("key");
        var vertex = PredictionServiceClient.Create();
        var gemini = new GoogleAI("key");
    }
}
