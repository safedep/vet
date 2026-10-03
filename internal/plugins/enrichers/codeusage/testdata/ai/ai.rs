use candle_core::{Device, Tensor};
use rig::providers::openai;
use ort::session::Session;
use tokenizers::Tokenizer;
use tiktoken_rs::cl100k_base;
use genai::Client;
use qdrant_client::Qdrant;
use fastembed::TextEmbedding;
use hf_hub::api::sync::Api;
use llama_cpp_2::llama_backend::LlamaBackend;
use mistralrs::TextModelBuilder;

fn run() {
    let t = Tensor::zeros((2, 2), candle_core::DType::F32, &Device::Cpu);
    let client = openai::Client::from_env();
    let session = Session::builder();
    let tok = Tokenizer::from_file("tokenizer.json");
    let bpe = cl100k_base();
    let genai = Client::default();
    let qdrant = Qdrant::from_url("http://localhost:6334").build();
    let embed = TextEmbedding::try_new(Default::default());
    let api = Api::new();
    let backend = LlamaBackend::init();
    let model = TextModelBuilder::new("microsoft/Phi-3.5-mini-instruct");
    let x = tch::Tensor::zeros(&[3], (tch::Kind::Float, tch::Device::Cpu));
    let lancedb = lancedb::connect("data");
    let linfa = linfa_linear::LinearRegression::new();
    let burn = burn::tensor::Tensor::<B, 1>::zeros([3], &device);
}
