using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using WebApplication3.Models;

namespace WebApplication3.Controllers
{
    public class HomeController : Controller
    {
        
        public IActionResult SetCookie()
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = Convert.FromBase64String("MWI4YzM0YWE4ZGZmNDM0ZTg1YzRkYzRlYzg3NDA2Mjg=");


            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            using MemoryStream msEncrypt = new MemoryStream();
            using CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write);

            msEncrypt.Write(iv, 0, iv.Length);

            byte[] plainBytes = Encoding.UTF8.GetBytes("Hello this is secret message");
            csEncrypt.Write(plainBytes, 0, plainBytes.Length);
            csEncrypt.FlushFinalBlock();

            string encryptedBase64 = Convert.ToBase64String(msEncrypt.ToArray());

            Response.Cookies.Append("MyEncryptedCookie", encryptedBase64);

            return Content("Cookie has been set.");
        }

        public IActionResult ReadCookie()
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = Convert.FromBase64String("MWI4YzM0YWE4ZGZmNDM0ZTg1YzRkYzRlYzg3NDA2Mjg=");


            byte[] encryptedBytes = Convert.FromBase64String(Request.Cookies["MyEncryptedCookie"]);
            byte[] iv = new byte[aesAlg.BlockSize / 8];
            Array.Copy(encryptedBytes, 0, iv, 0, iv.Length);
            aesAlg.IV = iv;

            using MemoryStream msDecrypt = new MemoryStream(encryptedBytes, iv.Length, encryptedBytes.Length - iv.Length);
            using CryptoStream csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read);
            using StreamReader srDecrypt = new StreamReader(csDecrypt);

            //return srDecrypt.ReadToEnd();
            // Retrieve the encrypted cookie value
            //string encryptedValue = Request.Cookies["MyEncryptedCookie"];

            // Decrypt the cookie value
            string decryptedValue = srDecrypt.ReadToEnd();

            return Content("Decrypted cookie value: " + decryptedValue);
        }
    }
}