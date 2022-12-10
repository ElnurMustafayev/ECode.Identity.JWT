namespace ECode.Identity.JWT.Options;

using System.Text;

public class JwtOption {
    public string EncryptionKey { get; set; }
    public byte[] EncryptionKeyInBytes { get; set; }
    public string Algorithm { get; set; }
    public double AccessTokenExpTimeInMinutes { get; set; }

    public JwtOption(string encryptionKey, string algorithm, double accessTokenExpTimeInMinutes) {
        ArgumentNullException.ThrowIfNull(encryptionKey, nameof(encryptionKey));
        ArgumentNullException.ThrowIfNull(algorithm, nameof(algorithm));

        if(accessTokenExpTimeInMinutes <= 0) {
            throw new ArgumentException("Expiration time can not be less than 0!", nameof(accessTokenExpTimeInMinutes));
        }

        this.EncryptionKey = encryptionKey;
        this.EncryptionKeyInBytes = Encoding.ASCII.GetBytes(this.EncryptionKey);

        this.Algorithm = algorithm;
        this.AccessTokenExpTimeInMinutes = accessTokenExpTimeInMinutes;
    }
}