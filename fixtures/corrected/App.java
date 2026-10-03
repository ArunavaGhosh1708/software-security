import java.io.*;
class App {
  public int read(InputStream input) throws Exception {
    return new DataInputStream(input).readInt();
  }
}
