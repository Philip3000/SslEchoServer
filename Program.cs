using System.Net;

namespace SslEchoServer
{
    class Program
    {
        private static int _port = 6789;
        private static IPAddress _serverAddress = IPAddress.Loopback;
        private static SslServer _sslserver;
        private static bool _clientConnected;
        private static bool _authenticated;
        private static string _serverCertificateFile = "C:/Users/phips/Certificates/echoServerContainer.pfx";
        private static string _serverCertificateFilePassword = "Rfe87epq";


        public static void Main(string[] args)
        {
            _sslserver = new SslServer(_serverAddress, _port, _serverCertificateFile, _serverCertificateFilePassword);
            _clientConnected = _sslserver.AcceptClient();
            if (_clientConnected)
            {
                _authenticated = _sslserver.AuthenticateAsServer();
            }
            if (_authenticated)
            {
                _sslserver.Talk();
            }

        }

    }
}
