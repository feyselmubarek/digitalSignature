using System;
using System.Text;
using System.Windows;

using System.Net;
using System.Net.Sockets;
using System.IO;
using Digital_Signature.Utilities;
using System.Threading;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Digital_Signature
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public StreamReader STR;
        public StreamWriter STW;
        public string receive;
        public string text_to_send;
        public string text_to_recieved;
        private string file;
        private HashFIle hashFile;

        public MainWindow()
        {
            InitializeComponent();
            progressTextBlock.Visibility = Visibility.Hidden;
            progressBar.Visibility = Visibility.Hidden;
            checkedBtn.Visibility = Visibility.Hidden;
        }

        private void ServeButton_Click(object sender, RoutedEventArgs e)
        {
            if(filePathTextBox.Text.ToString() != "")
            {
                ExecuteServer();
            }
            else
            {
                MessageBox.Show("Please choose file!!");
            }
        }

        private void ConnectServerBtn_Click(object sender, RoutedEventArgs e)
        {
            if (filePathTextBox.Text.ToString() != "")
            {
                ExecuteClient();
            }
            else
            {
                MessageBox.Show("Enter data!!");
            }
        }

        private void HashBtn_Click(object sender, RoutedEventArgs e)
        {
            progressTextBlock.Visibility = Visibility.Visible;
            progressTextBlock.Text = "Hashing in progress...";
            progressBar.Visibility = Visibility.Visible;
            checkedBtn.Visibility = Visibility.Hidden;

            Thread t = new Thread(perform);
            t.Start();
        }

        public async void ExecuteServer()
        {
            IPAddress[] ipHost = Dns.GetHostAddresses(Dns.GetHostName());
            IPAddress ip = null;
            foreach (IPAddress ipAddr in ipHost)
            {
                if (ipAddr.AddressFamily == AddressFamily.InterNetwork)
                {
                    ip = ipAddr;
                    ipAddressTextBox.Text = ipAddr.ToString();
                }
            }

            IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Parse(ipAddressTextBox.Text.ToString()), int.Parse(portTextBox.Text));
            consoleTextBox.AppendText("Shell >> Ip Address: " + ipAddressTextBox.Text.ToString() + ":" + portTextBox.Text.ToString() + "\n");

            progressTextBlock.Visibility = Visibility.Visible;
            checkedBtn.Visibility = Visibility.Hidden;
            progressTextBlock.Text = "Waiting connection ..." + "\n";
            progressBar.Visibility = Visibility.Visible;

            Socket listener = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                while (true)
                {
                    Socket clientSocket = await listener.AcceptAsync();


                    if(clientSocket != null)
                    {
                        progressTextBlock.Text = "Client Joined ..." + "\n";
                        progressBar.Visibility = Visibility.Hidden;
                        checkedBtn.Visibility = Visibility.Visible;
                    }
                    
                    byte[] bytes = new Byte[4096];
                    string data = null;

                    while (true)
                    { 
                        int numByte = clientSocket.Receive(bytes);
                        data += Encoding.ASCII.GetString(bytes, 0, numByte);

                        if (data.IndexOf("<EOF>") > -1)
                            break;
                    }

                    data = data.Substring(0, (data.Length - 5));
                    consoleTextBox.AppendText($"Shell >> Text received -> {0} " + data + "\n");
                    byte[] message = Encoding.ASCII.GetBytes(text_to_send + "<EOF>");

                    clientSocket.Send(message);

                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                }
            }

            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        public void ExecuteClient()
        {
            try
            {
                IPAddress ipAddr = IPAddress.Parse(ipAddressTextBox.Text);
                IPEndPoint localEndPoint = new IPEndPoint(ipAddr, int.Parse(portTextBox.Text));

                Socket sender = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    sender.Connect(localEndPoint);

                    consoleTextBox.AppendText($"Shell >> Socket connected to -> {0} " + sender.RemoteEndPoint.ToString() + "\n");

                    byte[] messageSent = Encoding.ASCII.GetBytes(filePathTextBox.Text.ToString() + "<EOF>");
                    int byteSent = sender.Send(messageSent);
                    
                    byte[] messageReceived = new byte[1024];
                    
                    int byteRecv = sender.Receive(messageReceived);

                    text_to_recieved = Encoding.ASCII.GetString(messageReceived, 0, byteRecv);

                    consoleTextBox.AppendText($"Message from Server -> {0}" + Encoding.ASCII.GetString(messageReceived, 0, byteRecv) + "\n");

                    sender.Shutdown(SocketShutdown.Both);
                    sender.Close();
                }
                catch (ArgumentNullException ane)
                {
                    MessageBox.Show($"ArgumentNullException : {0}", ane.ToString() + "null exception ");
                }
                catch (SocketException se)
                {
                    MessageBox.Show($"SocketException : {0}", se.ToString() + "socket exception");
                }
                catch (Exception e)
                {
                    MessageBox.Show($"Unexpected exception : {0}", e.ToString() + "other");
                }
            }catch (Exception e){
                MessageBox.Show(e.ToString());
            }
        }

        private void ReadFile()
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();

            bool? result = dlg.ShowDialog();
 
            string filename = null;
            if (result == true)
            {
                filename = dlg.FileName;
                file = filename;
                filePathTextBox.Text = filename;
            }

            using (var fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                var sr = new StreamReader(fileStream, Encoding.UTF8);
                string content = sr.ReadToEnd();
                consoleTextBox.Text = content;
                hashFile = new HashFIle(content);
            }
        }

        private void NewFile_Click(object sender, RoutedEventArgs e)
        {
            ReadFile();
        }

        private void perform()
        {
            hashFile.MakeHashKeys();
            string publicKey = hashFile.getPublicKey();
            text_to_send = hashFile.GenerateSignature();
            text_to_send = text_to_send + "~" + publicKey + "~" + file;

            this.Dispatcher.Invoke(() =>
            {
                consoleTextBox.AppendText("\nShell >> publicKey is " + publicKey + "\n");
                progressTextBlock.Visibility = Visibility.Visible;
                progressTextBlock.Text = "Hashing Finished...";
                progressBar.Visibility = Visibility.Hidden;
                checkedBtn.Visibility = Visibility.Visible;
            });
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            string[] arr = text_to_recieved.Split('~');
            string publicKey = arr[0];
            string signature = arr[1];
            string filePath = arr[2];

            byte[] publicKeyDerRestored = Convert.FromBase64String(publicKey);
            RsaKeyParameters publicKeyRestored = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyDerRestored);

            hashFile.VerifySignature(signature);
        }
    }
}
