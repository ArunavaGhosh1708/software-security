import java.io.*;
class App {
  public Object read(InputStream input) throws Exception {
    return new ObjectInputStream(input).readObject();
  }
}
