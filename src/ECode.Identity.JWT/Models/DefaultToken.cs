namespace ECode.Identity.JWT.Models;

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

public class DefaultToken {
    [JsonPropertyName("exp")]
    public long ExpirationTime { get; set; }

    [JsonPropertyName("iss")]
    public string? Issuer { get; set; }

    [JsonPropertyName("aud")]
    public string? Audience { get; set; }

    [JsonIgnore]
    public string? PayloadJson { get; set; }

    public T GetValue<T>(string param) {
        ArgumentNullException.ThrowIfNull(param, nameof(param));

        if(string.IsNullOrWhiteSpace(this.PayloadJson)) {
            throw new Exception("JsonPayload is empty. Incorrect Token parsing.");
        }

        var jsonNode = JsonNode.Parse(this.PayloadJson);

        if(jsonNode == null) {
            throw new JsonException("Payload couldn't parse");
        }

        var result = jsonNode[param];

        if(result == null && (result = jsonNode[param.ToLower(CultureInfo.CurrentCulture)]) == null) {
            throw new Exception($"Field {result} not found in Payload");
        }

        return result.GetValue<T>();
    }


    public string this[string param] => this.GetValue<string>(param);


    public override string ToString() => @$"Expiration Time: {this.ExpirationTime}
Issuer: {this.Issuer}
Audience: {this.Audience}";
}