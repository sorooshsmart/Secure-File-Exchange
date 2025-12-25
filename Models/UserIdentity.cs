using System.Security.Cryptography;

namespace SecureFileExchange.Models
{
    public class UserIdentity
    {
        public string Username { get; set; } = string.Empty;
        public RSAParameters EncryptionPublicKey { get; set; }
        public RSAParameters SigningPublicKey { get; set; }
        public RSAParameters? EncryptionPrivateKey { get; set; }
        public RSAParameters? SigningPrivateKey { get; set; }
        public string UserDirectory { get; set; } = string.Empty;
    }

    public class UserCredentials
    {
        public string Username { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
    }

    public class SessionContext
    {
        private static SessionContext? _instance;
        private static readonly object _lock = new object();

        public UserIdentity? CurrentUser { get; private set; }
        public bool IsAuthenticated => CurrentUser != null;

        private SessionContext() { }

        public static SessionContext Instance
        {
            get
            {
                lock (_lock)
                {
                    if (_instance == null)
                    {
                        _instance = new SessionContext();
                    }
                    return _instance;
                }
            }
        }

        public void Login(UserIdentity user)
        {
            CurrentUser = user;
        }

        public void Logout()
        {
            // Clear sensitive data
            if (CurrentUser?.EncryptionPrivateKey != null)
            {
                ClearRSAParameters(CurrentUser.EncryptionPrivateKey.Value);
            }
            if (CurrentUser?.SigningPrivateKey != null)
            {
                ClearRSAParameters(CurrentUser.SigningPrivateKey.Value);
            }
            CurrentUser = null;
        }

        private void ClearRSAParameters(RSAParameters parameters)
        {
            if (parameters.D != null) Array.Clear(parameters.D, 0, parameters.D.Length);
            if (parameters.P != null) Array.Clear(parameters.P, 0, parameters.P.Length);
            if (parameters.Q != null) Array.Clear(parameters.Q, 0, parameters.Q.Length);
            if (parameters.DP != null) Array.Clear(parameters.DP, 0, parameters.DP.Length);
            if (parameters.DQ != null) Array.Clear(parameters.DQ, 0, parameters.DQ.Length);
            if (parameters.InverseQ != null) Array.Clear(parameters.InverseQ, 0, parameters.InverseQ.Length);
        }
    }
}