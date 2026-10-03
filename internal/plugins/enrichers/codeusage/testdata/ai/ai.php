<?php

use Prism\Prism\Prism;
use Prism\Prism\Enums\Provider;
use LLPhant\Chat\OpenAIChat;
use NeuronAI\Agent;
use Rubix\ML\Classifiers\KNearestNeighbors;
use Codewithkyrian\Transformers\Pipelines;
use Phpml\Classification\KNearestNeighbors as PhpmlKnn;
use Symfony\AI\Platform\Bridge\OpenAi\PlatformFactory;
use Yethee\Tiktoken\EncoderProvider;
use LarAgent\Agent as LarAgentAgent;

$response = Prism::text()->using(Provider::Anthropic, 'claude-sonnet-4-5')->withPrompt('hi')->asText();
$chat = new OpenAIChat();
$agent = Agent::make();
$knn = new KNearestNeighbors(3);
$classifier = Pipelines\pipeline('sentiment-analysis');
$phpml = new PhpmlKnn();
$platform = PlatformFactory::create(getenv('OPENAI_API_KEY'));
$encoder = (new EncoderProvider())->getForModel('gpt-4o');
$gemini = Gemini::client(getenv('GEMINI_API_KEY'));
