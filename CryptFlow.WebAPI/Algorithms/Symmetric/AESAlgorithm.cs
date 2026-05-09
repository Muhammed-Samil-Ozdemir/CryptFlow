using System.Security.Cryptography;
using System.Text;

namespace CryptFlow.WebAPI.Algorithms.Symmetric;

public class AESAlgorithm : ISymmetricAlgorithm
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public string AlgorithmName => "AES";
    public int KeySize => 256;
    
    public AESAlgorithm()
    {
        _key = GenerateKey();
        _iv = GenerateIV();
    }
    
    public AESAlgorithm(byte[] key, byte[] iv)
    {
        _key = key;
        _iv = iv;
    }

    
    
    
    public string Encrypt(string plainText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        
        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        
        return Convert.ToBase64String(cipherBytes);
    }

    public string Decrypt(string cipherText)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        
        using var decryptor = aes.CreateDecryptor();
        var cipherBytes = Convert.FromBase64String(cipherText);
        var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
        
        return Encoding.UTF8.GetString(plainBytes);
    }

    public byte[] GenerateKey()
    {
        using var aes = Aes.Create();
        aes.KeySize = KeySize;
        aes.GenerateKey();
        
        return aes.Key;
    }

    public byte[] GenerateIV()
    {
        using var aes = Aes.Create();
        aes.GenerateIV();
        
        return aes.IV;
    }
}