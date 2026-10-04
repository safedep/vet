using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

class Onnx
{
    void Run()
    {
        using var session = new InferenceSession("model.onnx");
        var input = new DenseTensor<float>(new[] { 1, 3 });
    }
}
