using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace SHA256_SignatureAlgorithm
{
    class Program
    {
        private static bool _optimalAsymmetricEncryptionPadding = false;
        static void Main(string[] args)
        {
            Console.WriteLine("Please enter message for which you want to create signature");
            string message = Console.ReadLine();
            int keySize = 1024;
            string privateKeyXml = Directory.GetCurrentDirectory().Split("bin")[0] + "/keystore_name.xml";
            var encrypted = EncryptByteArray(Encoding.UTF8.GetBytes(message), privateKeyXml, keySize);
            var signature = Convert.ToBase64String(encrypted);
            Console.WriteLine("Your signature is :");
            Console.Write(signature);
            Console.Read();

        }

        /// <summary>
        /// Encrypt byte array
        /// </summary>       
        /// <param name="data">The text message in byte array format</param>
        /// <param name="privateKeyXml">The private key in XML format</param>
        /// <param name="data">The keySize which is 1024 bit in length</param>
        /// <returns>Signature created in byte array format</returns>
        private static byte[] EncryptByteArray(byte[] data, string privateKeyXml, int keySize)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentException(Constants.DataEmpty, "data");
            }

            int maxLength = GetMaxDataLength(keySize);

            if (data.Length > maxLength)
            {
                throw new ArgumentException(String.Format("Maximum data length is {0}", maxLength), "data");
            }

            if (!IsKeySizeValid(keySize))
            {
                throw new ArgumentException(Constants.InvalidKeySize, "keySize");
            }

            if (String.IsNullOrEmpty(privateKeyXml))
            {
                throw new ArgumentException(Constants.KeyIsNullOrEmpty, "privateKeyXml");
            }

            using (var provider = new RSACryptoServiceProvider(keySize))
            {
                FromXml(provider, privateKeyXml);
                return provider.SignData(data, CryptoConfig.MapNameToOID(Constants.SHA256));
            }
        }
        /// <summary>
        /// Calculate parameters from XML file
        /// </summary>       
        /// <param name="rsa">The RSA key length</param>
        /// <param name="xmlString">The XML string</param>
        /// <returns>void</returns>
        private static void FromXml(RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals(Constants.RSAKeyValue))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case Constants.Modulus: parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.Exponent: parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.P: parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.Q: parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.DP: parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.DQ: parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.InverseQ: parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case Constants.D: parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception(Constants.InvalidXMLRSAkey);
            }

            rsa.ImportParameters(parameters);
        }
        /// <summary>
        /// Checks if the Data length
        /// </summary>       
        /// <param name="keySize">The key length</param>
        /// <returns>Data length</returns>
        public static int GetMaxDataLength(int keySize)
        {
            if (_optimalAsymmetricEncryptionPadding)
            {
                return ((keySize - 384) / 8) + 7;
            }
            return ((keySize - 384) / 8) + 37;
        }

        /// <summary>
        /// Checks if the given key size if valid
        /// </summary>       
        /// <param name="keySize">The RSA key length</param>
        /// <returns>True if valid; false otherwise</returns>
        public static bool IsKeySizeValid(int keySize)
        {
            return keySize >= 384 &&
                   keySize <= 16384 &&
                   keySize % 8 == 0;
        }
    }
}
