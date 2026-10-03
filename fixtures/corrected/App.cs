using System.Text.Json;
class App {
  string Read(string input) {
    return JsonSerializer.Deserialize<string>(input);
  }
}
