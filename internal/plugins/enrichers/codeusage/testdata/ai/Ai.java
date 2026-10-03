import ai.djl.repository.zoo.Criteria;
import ai.onnxruntime.OrtEnvironment;
import org.tensorflow.SavedModelBundle;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.nd4j.linalg.factory.Nd4j;
import org.tribuo.classification.sgd.linear.LogisticRegressionTrainer;
import com.google.cloud.vertexai.VertexAI;
import io.milvus.v2.client.MilvusClientV2;
import io.qdrant.client.QdrantClient;
import io.pinecone.clients.Pinecone;
import io.weaviate.client.WeaviateClient;
import com.knuddels.jtokkit.Encodings;
import dev.langchain4j.model.openai.OpenAiChatModel;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import smile.classification.RandomForest;

class Ai {
    void run() throws Exception {
        Criteria.builder().build();
        OrtEnvironment.getEnvironment();
        SavedModelBundle.load("model", "serve");
        new MultiLayerNetwork(null);
        Nd4j.zeros(3);
        new LogisticRegressionTrainer();
        new VertexAI("p", "us-central1");
        new MilvusClientV2(null);
        new QdrantClient(null);
        new Pinecone.Builder("k").build();
        new WeaviateClient(null);
        Encodings.newDefaultEncodingRegistry();
        OpenAiChatModel.builder().build();
        AnthropicOkHttpClient.fromEnv();
        RandomForest.fit(null, null);
    }
}
