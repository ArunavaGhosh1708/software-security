using System.Runtime.Serialization.Formatters.Binary;
class App {
  object Read(System.IO.Stream input) {
    return new BinaryFormatter().Deserialize(input);
  }
}
