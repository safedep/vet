require 'ruby_llm'
require 'gemini-ai'
require 'omniai/openai'
require 'torch'
require 'tiktoken_ruby'
require 'informers'
require 'onnxruntime'
require 'rumale'
require 'qdrant'
require 'dspy'

chat = RubyLLM.chat(model: 'gpt-4o')
chat.ask('hi')
RubyLLM.embed('hello')
gemini = Gemini.new(credentials: { service: 'generative-language-api', api_key: ENV['KEY'] })
omni = OmniAI::OpenAI::Client.new
x = Torch.tensor([1, 2, 3])
layer = Torch::NN::Linear.new(4, 2)
enc = Tiktoken.encoding_for_model('gpt-4o')
classifier = Informers.pipeline('sentiment-analysis')
model = OnnxRuntime::Model.new('model.onnx')
svc = Rumale::LinearModel::LogisticRegression.new
qdrant = Qdrant::Client.new(url: 'http://localhost:6333')
predict = DSPy::Predict.new(Signature)
