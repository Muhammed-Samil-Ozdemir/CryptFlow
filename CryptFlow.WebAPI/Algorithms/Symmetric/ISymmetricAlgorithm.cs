namespace CryptFlow.WebAPI.Algorithms.Symmetric;

public interface ISymmetricAlgorithm
{
    string AlgorithmName { get; }
    int KeySize { get; }

    string Encrypt(string plainText);
    string Decrypt(string cipherText);
    byte[] GenerateKey();
    byte[] GenerateIV();
}