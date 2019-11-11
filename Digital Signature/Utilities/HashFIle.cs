using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Digital_Signature.Utilities
{
    class HashFIle
    {
        private string SourceData;
        private RsaKeyParameters privateKey;
        public RsaKeyParameters publicKey;
        private byte[] tmpSource;

        public HashFIle(string SourceData)
        {
            this.SourceData = SourceData;
            tmpSource = Encoding.ASCII.GetBytes(SourceData);
        }

        public void MakeHashKeys()
        {
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Key pairs are Generating... Please wait for few moments...");
            Console.WriteLine();
            Console.WriteLine();

            RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
            rsaKeyPairGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = rsaKeyPairGen.GenerateKeyPair();

            RsaKeyParameters privateKey = (RsaKeyParameters)keyPair.Private;
            RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;

            this.privateKey = privateKey;
            this.publicKey = publicKey;        
        }

        public string getPublicKey()
        {
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);

            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();
            string print_publickey = textWriter.ToString();

            byte[] publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();
            string publicKeyDerBase64 = Convert.ToBase64String(publicKeyDer);

            return publicKeyDerBase64;
        }

        private static string ByteArrayToString(byte[] arrInput)
        {
            int i;
            StringBuilder sOutput = new StringBuilder(arrInput.Length);
            for (i = 0; i < arrInput.Length; i++)
            {
                sOutput.Append(arrInput[i].ToString("X").ToLower());
            }
            return sOutput.ToString();
        }

        public bool VerifySignature(RsaKeyParameters publicKey, byte[] tmpSource, byte[] signature)
        {
            ISigner sign1 = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id);
            sign1.Init(false, publicKey);
            sign1.BlockUpdate(tmpSource, 0, tmpSource.Length);
            bool status = sign1.VerifySignature(signature);

            return status;
        }

        public string GenerateSignature()
        {
            ISigner sign = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id);
            sign.Init(true, privateKey);
            sign.BlockUpdate(tmpSource, 0, tmpSource.Length);
            byte[] signature = sign.GenerateSignature();

            return ByteArrayToString(signature);
        }
    }
}
