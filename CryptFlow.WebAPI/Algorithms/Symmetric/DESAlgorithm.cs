using System.Security.Cryptography;
using System.Text;

namespace CryptFlow.WebAPI.Algorithms.Symmetric;

public class DESAlgorithm : ISymmetricAlgorithm
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public string AlgorithmName => "DES";
    public int KeySize => 64;
    
    public DESAlgorithm()
    {
        _key = GenerateKey();
        _iv = GenerateIV();
    }

    public DESAlgorithm(byte[] key, byte[] iv)
    {
        _key = key;
        _iv = iv;
    }

    public string Encrypt(string plainText)
    {
        using var des = DES.Create();
        des.Key = _key;
        des.IV  = _iv;
        
        using var encryptor = des.CreateEncryptor();
        var bytes = Encoding.UTF8.GetBytes(plainText);
        
        return Convert.ToBase64String(encryptor.TransformFinalBlock(bytes, 0, bytes.Length));
    }

    public string Decrypt(string cipherText)
    {
        using var des = DES.Create();
        des.Key = _key;
        des.IV  = _iv;
        
        using var decryptor = des.CreateDecryptor();
        var bytes = Convert.FromBase64String(cipherText);
        
        return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(bytes, 0, bytes.Length));
    }

    public byte[] GenerateKey()
    {
        using var des = DES.Create();
        des.GenerateKey();
        
        return des.Key;
    }

    public byte[] GenerateIV()
    {
        using var des = DES.Create();
        des.GenerateIV();
        
        return des.IV;
    }
}