namespace ECode.Identity.JWT.Helpers;

using ECode.Identity.JWT.Models;
using System.Text.Json;
using System.Text;

public static class JwtParser {
    public static DefaultToken Parse(string jwt) {
        var tokenObj = Parse<DefaultToken>(jwt);
        tokenObj.PayloadJson = GetPayload(jwt);

        return tokenObj;
    }



    public static TTokent Parse<TTokent>(string jwt) {
        ArgumentNullException.ThrowIfNull(jwt, nameof(jwt));

        var decodedPayload = GetPayload(jwt);

        return JsonSerializer.Deserialize<TTokent>(decodedPayload)!;
    }



    private static string GetPayload(string jwt) {
        ArgumentNullException.ThrowIfNull(jwt, nameof(jwt));

        var tokenParts = jwt.Split('.', StringSplitOptions.RemoveEmptyEntries);

        if(tokenParts.Length != 3) {
            throw new FormatException($"Token format is invalid. JWT: '{jwt}'");
        }

        // get payload part of token
        var payloadBase64 = tokenParts[1];
        payloadBase64 = payloadBase64.PadRight(payloadBase64.Length + payloadBase64.Length * 3 % 4, '=');

        var payloadInBytes = Convert.FromBase64String(payloadBase64);

        // decode payload part into utf-8
        return Encoding.UTF8.GetString(payloadInBytes);
    }
}