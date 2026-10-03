import java.util.ArrayList;
import com.example.ml.Model;

class Plain {
    void run() {
        new StringBuilder("a").append("b");
        new ArrayList<String>().add("x");
        new Model("m").predict();
    }
}
