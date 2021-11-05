using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Mesajlaşma_Uygulaması
{
    public partial class Form1 : Form
    {
        SqlConnection conn;
        SqlCommand cmnd;
        SqlDataReader dr;
        string kullanici;
        string pKey;
        string publicKey;
        string otherPublicKey;     
        public Form1()
        {
            InitializeComponent();
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            conn = new SqlConnection(@"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=C:\Users\Kaan\database.mdf;Integrated Security=False"); //Veri Tabanı Bağlantısı
        }
        private void button1_Click(object sender, EventArgs e) //Mesaj Gönder Butonu
        {
            conn.Open();
            cmnd = new SqlCommand("INSERT INTO Mesaj (kullaniciAdi, Tarih, gelenMesaj,aliciKullaniciAdi) values(@a1, @a2, @a3,@a4)", conn);
            cmnd.Parameters.AddWithValue("@a1", textBox2.Text);
            cmnd.Parameters.AddWithValue("@a2", DateTime.Now.ToString("MM/dd/yyyy HH:mm"));
            cmnd.Parameters.AddWithValue("@a3", sifreleAES(sifreleDH())); //Önce Diffie-Hellman sonra AES ile şifreliyor.
            cmnd.Parameters.AddWithValue("@a4", textBox3.Text);
            cmnd.ExecuteNonQuery();
            conn.Close();
            textBox1.Text = "";
        }
        private void button2_Click(object sender, EventArgs e) //Giriş/Kayıt Ol butonu
        {
            FileStream fw;
            StreamWriter sw;
            var ecdh = GetNewEcdhProvider(384);           
            conn.Open();
            cmnd = new SqlCommand("SELECT * FROM Uye", conn);
            dr = cmnd.ExecuteReader();
            while (dr.Read()) // Yeni kullanıcı var mı diye kontrol ediyor.
            {
                if (textBox2.Text == dr[1].ToString())
                {
                    kullanici = textBox2.Text;
                    publicKey = dr[2].ToString(); //Public keyi tutuyor.
                }
            }
            conn.Close();
            if (kullanici == null) //Kullanıcı yoksa kayıt oluşturuyor.
            {
                if (!File.Exists(@"C:\privateKeys\" + textBox2.Text)) //Gizli anahtarın dosyası, o kullanıcı için var mı diye kontrol ediyor.
                {
                    fw = new FileStream(@"C:\privateKeys\" + textBox2.Text, FileMode.OpenOrCreate, FileAccess.Write); //Kullanıcıya gizli anahtar için dosya oluşturuyor.
                    sw = new StreamWriter(fw);
                    sw.WriteLine(ToBase64(ecdh.Key.Export(CngKeyBlobFormat.EccPrivateBlob))); //Gizli anahtarı dosyaya yazıyor.
                    sw.Close();
                    fw.Close();
                }
                publicKey = ToBase64(ecdh.Key.Export(CngKeyBlobFormat.EccPublicBlob)); // Public keyi tutuyor.
                cmnd = new SqlCommand("INSERT INTO Uye (kullaniciAdi,publicKey) values(@a1, @a2)", conn);
                cmnd.Parameters.AddWithValue("@a1", textBox2.Text);
                cmnd.Parameters.AddWithValue("@a2", publicKey);
                conn.Open();
                cmnd.ExecuteNonQuery();
                conn.Close();
                MessageBox.Show("Kullanıcı eklendi.");
            }
            pKey = File.ReadAllText(@"C:\privateKeys\" + textBox2.Text); //Gizli anahtarı kullanıcının dosyasından çekiyor.
            textBox2.Enabled = false;
            button2.Enabled = false;
        }

        private void button3_Click(object sender, EventArgs e) //Alıcıyı Seçme Butonu
        {
            cmnd = new SqlCommand("SELECT * FROM Uye", conn);
            conn.Open();
            dr = cmnd.ExecuteReader();
            while (dr.Read()) //Alıcının sistemde kayıtlı olup olmadığını kontrol ediyor.
            {
                if (textBox3.Text == dr[1].ToString())
                {
                    textBox3.Enabled = false;
                    button3.Enabled = false;
                    otherPublicKey = dr[2].ToString();
                }
            }
            conn.Close();
            if (textBox3.Enabled == true)
            {
                textBox3.Text = "";
                MessageBox.Show("Kullanıcı bulunamadı");
            }
        }

        private void timer1_Tick(object sender, EventArgs e) //Mesajlaşma kutusunu yenilenmesi
        {
            if (textBox3.Enabled == false)
            {
                mesajlar.Clear();
                cmnd = new SqlCommand("SELECT * FROM Mesaj Where (kullaniciAdi = @a1 AND aliciKullaniciAdi = @a2) OR (kullaniciAdi = @a2 AND aliciKullaniciAdi = @a1)", conn); //İki kullanıcı arasındaki mesajlar çekiliyor
                cmnd.Parameters.AddWithValue("@a1", textBox2.Text);
                cmnd.Parameters.AddWithValue("@a2", textBox3.Text);
                conn.Open();
                dr = cmnd.ExecuteReader();
                while (dr.Read())
                {
                    mesajlar.Text = mesajlar.Text + "\n" + dr[1].ToString() + " (" + dr[2].ToString() + "): " + sifreCozDH(sifreCozAES(dr[3].ToString())); //Önce AES sonra Diffie-Hellman ile çözüyor.
                }
                conn.Close();
                mesajlar.SelectionStart = mesajlar.Text.Length;
                mesajlar.ScrollToCaret();
            }
        }
        ECDiffieHellmanCng GetNewEcdhProvider(int dwKeySize = 512) //yeni bir ECDH protokolü oluşturuyor.
        {
            var alg = CngAlgorithm.ECDiffieHellmanP256;
            if (dwKeySize == 384)
                alg = CngAlgorithm.ECDiffieHellmanP384;
            if (dwKeySize == 512)
                alg = CngAlgorithm.ECDiffieHellmanP521;
            var key = CngKey.Create(alg, null, GetKeyParameters());
            var ecdh = new ECDiffieHellmanCng(key);
            return ecdh;
        }
        public static string ToBase64(byte[] bytes) //girilen veriyi base64 haline çeviriyor.
        {
            var s = Convert.ToBase64String(bytes);
            s = InsertNewLines(s, 64);
            return s;
        }
        CngKeyCreationParameters GetKeyParameters()
        {
            var parameters = new CngKeyCreationParameters();
            parameters.ExportPolicy = CngExportPolicies.AllowPlaintextExport;	
            parameters.KeyCreationOptions |= CngKeyCreationOptions.MachineKey;
            return parameters;
        }
        public static string InsertNewLines(string s, int len)
        {
            var sb = new StringBuilder(s.Length + (s.Length / len) + 1);
            int start;
            for (start = 0; start < s.Length - len; start += len)
            {
                sb.Append(s.Substring(start, len));
                sb.Append(Environment.NewLine);
            }
            sb.Append(s.Substring(start));
            return sb.ToString();
        }//Girilen stringi satırlara ayırıyor.
        private static RNGCryptoServiceProvider _random = new RNGCryptoServiceProvider();
        private static int _randomSize = 256 / 8;
        public static byte[] AddRandom(byte[] bytes)
        {
            var ms = new MemoryStream();
            var randomBytes = new byte[_randomSize];
            _random.GetBytes(randomBytes);
            ms.Write(randomBytes, 0, randomBytes.Length);
            ms.Write(bytes, 0, bytes.Length);
            var resultBytes = ms.ToArray();
            ms.Dispose();
            return resultBytes;
        } //Rastgele byte atıyor.
        public static byte[] RemoveRandom(byte[] bytes)
        {
            var data = new byte[bytes.Length - _randomSize];
            Array.Copy(bytes, _randomSize, data, 0, data.Length);
            return data;
        }
        private string sifreleDH() // Diffie-Hellman kullanarak şifreleme
        {
                var keyBlob = System.Convert.FromBase64String(pKey); //Gizli Anahtarı yeni bir ecdh oluşturmak için base64'e çeviriyor.
                var privateKey = CngKey.Import(keyBlob, CngKeyBlobFormat.EccPrivateBlob);
                var ecdh = new System.Security.Cryptography.ECDiffieHellmanCng(privateKey);
                var otherPartyKeyBlob = System.Convert.FromBase64String(otherPublicKey); //Alıcının publicKeyini alıyoruz.
                var otherPartyPublicKey = CngKey.Import(otherPartyKeyBlob, CngKeyBlobFormat.EccPublicBlob);
                var symetricKey = ecdh.DeriveKeyMaterial(otherPartyPublicKey); //Alıcının public Keyini simetrik anahtara çevirip, base64 biçimine alıyoruz.
                var symetricKeyBase64 = ToBase64(symetricKey);
                var dataBytes = System.Text.Encoding.UTF8.GetBytes(textBox1.Text); //Mesaj(textBox1.Text) byte'larını rastgele bir biçimde simetrik anahtar ile şifreliyoruz.
                dataBytes = AddRandom(dataBytes);
                var encryptedBytes = Encrypt(symetricKey, dataBytes);
                var encryptedBase64 = ToBase64(encryptedBytes);
                
                return encryptedBase64.ToString(); //Şifreli anahtarı dönüyor.

        }

        public static byte[] Encrypt(byte[] password, byte[] bytes) //Şifreleme metodu
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            var encryptor = GetTransform(password, true);
            var encryptedBytes = CipherStreamWrite(encryptor, bytes);
            encryptor.Dispose();
            return encryptedBytes;
        }
        public static byte[] Decrypt(byte[] password, byte[] bytes) //Çözme Metodu.
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));
            var decryptor = GetTransform(password, false);
            var decryptedBytes = CipherStreamWrite(decryptor, bytes);
            decryptor.Dispose();
            return decryptedBytes;
        }
        private static ICryptoTransform GetTransform(byte[] password, bool encrypt)
        {
            var provider = new AesCryptoServiceProvider();
            var salt = SaltFromPassword(password);
            var secretKey = new Rfc2898DeriveBytes(password, salt, 10);
            var key = secretKey.GetBytes(provider.KeySize / 8);
            var iv = secretKey.GetBytes(provider.BlockSize / 8);
            secretKey.Dispose();
            var cryptor = encrypt
                ? provider.CreateEncryptor(key, iv)
                : provider.CreateDecryptor(key, iv);
            return cryptor;
        }
        private static byte[] SaltFromPassword(byte[] passwordBytes)
        {
            var algorithm = new HMACSHA256();
            algorithm.Key = passwordBytes;
            var salt = algorithm.ComputeHash(passwordBytes);
            algorithm.Dispose();
            return salt;
        }

        /// <summary>
        /// Encrypt/Decrypt with Write method.
        /// </summary>
        /// <param name="cryptor"></param>
        /// <param name="input"></param>
        /// <returns></returns>
        private static byte[] CipherStreamWrite(ICryptoTransform cryptor, byte[] input)
        {
            var inputBuffer = new byte[input.Length];
            System.Buffer.BlockCopy(input, 0, inputBuffer, 0, inputBuffer.Length); 
            var stream = new System.IO.MemoryStream();
            var cryptoStream = new CryptoStream(stream, cryptor, CryptoStreamMode.Write); //Çözme ve Şifreleme işlemini başlatıyor.
            cryptoStream.Write(inputBuffer, 0, inputBuffer.Length);
            cryptoStream.FlushFinalBlock(); // Çözme ve Şifreleme işlemi bitiyor.
            var outputBuffer = stream.ToArray(); //MemoryStreamden Byte'a çeviriyoruz.
            cryptoStream.Close();
            return outputBuffer;
        }
        private string sifreCozDH(string mesaj) //Diffie-Hellman Şifre Çözme
        {
                var keyBlob = System.Convert.FromBase64String(pKey); // Gizli Anahtarı yeni bir ecdh oluşturmak için base64'e çeviriyor.
                var privateKey = CngKey.Import(keyBlob, CngKeyBlobFormat.EccPrivateBlob);
                var ecdh = new System.Security.Cryptography.ECDiffieHellmanCng(privateKey);
                var otherPartyKeyBlob = System.Convert.FromBase64String(otherPublicKey); //Alıcının publicKeyini alıyoruz.
                var otherPartyPublicKey = CngKey.Import(otherPartyKeyBlob, CngKeyBlobFormat.EccPublicBlob);
                var symetricKey = ecdh.DeriveKeyMaterial(otherPartyPublicKey); //Alıcının public Keyini simetrik anahtara çevirip, base64 biçimine alıyoruz.
            var symetricKeyBase64 = ToBase64(symetricKey);
                var encryptedBytes = System.Convert.FromBase64String(mesaj);  //Şifrelenmiş mesajı alıp çözme işlemi başlıyor.
                var decryptedBytes = Decrypt(symetricKey, encryptedBytes);
                decryptedBytes = RemoveRandom(decryptedBytes);
                var decryptedData = System.Text.Encoding.UTF8.GetString(decryptedBytes);

                return decryptedData.ToString();
        }
        public string sifreleAES(string clearText) //AES ile şifreleme
        {
            string EncryptionKey = "KAAN10EMIN"; //Şifreleme Anahtarı
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }
        public string sifreCozAES(string cipherText) //AES ile çözme
        {
            string EncryptionKey = "KAAN10EMIN"; //Şifreleme Anahtarı
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
    }
}