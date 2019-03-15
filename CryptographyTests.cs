using System.Security.Cryptography;
using Neo.Core.Cryptography;
using Xunit;

namespace Neo.Tests
{
    public class CryptographyTests
    {
        private readonly AesParameters params1 = NeoCryptoProvider.Instance.GetRandomData();
        private readonly AesParameters params2 = NeoCryptoProvider.Instance.GetRandomData();
        private readonly string s = "Herbert-Meyer-Straße 3, 29556 Suderburg";

        [Fact]
        public void CanComputeHash() {
            var hash1 = NeoCryptoProvider.Instance.Sha512ComputeHash(s);
            var hash2 = NeoCryptoProvider.Instance.Sha512ComputeHash(s);

            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void CanEncrypt() {
            var encrypted = NeoCryptoProvider.Instance.AesEncrypt(s, params1);
            
            Assert.False(string.IsNullOrEmpty(encrypted));
        }

        [Fact]
        public void CanDecryptWithCorrectParameters() {
            var encrypted = NeoCryptoProvider.Instance.AesEncrypt(s, params1);
            var decrypted = NeoCryptoProvider.Instance.AesDecrypt(encrypted, params1);

            Assert.Equal(decrypted, s);
        }

        [Fact]
        public void CantDecryptWithWrongParameters() {
            var encrypted = NeoCryptoProvider.Instance.AesEncrypt(s, params1);

            Assert.Throws<CryptographicException>(() => NeoCryptoProvider.Instance.AesDecrypt(encrypted, params2));
        }

        [Fact]
        public void CanGenerateValidAesParameters() {
            var aesParams = NeoCryptoProvider.Instance.GetRandomData();

            Assert.True(aesParams.IsValid());
        }
    }
}