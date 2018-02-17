using System;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Queue;
using SecurityDriven.Inferno;
using SecurityDriven.Inferno.Extensions;
using SecurityDriven.Inferno.Kdf;
using SecurityDriven.Inferno.Mac;

namespace DeveloperSecrets.Sender {
    class Program {
        private const string CONNECTION_STRING = "UseDevelopmentStorage=true";
        private const string QUEUE_NAME = "generation-3";

        static void Main(string[] args) {
            // Set colors to green on black, because everyone knows that's what hackers use
            Console.ForegroundColor = ConsoleColor.Green;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.Clear();

            // Show banner
            Console.WriteLine("Developer Secrets Sender - Generation 3 (symmetric encryption with key derivation)");
            Console.WriteLine("Copyright (c) Michal A. Valasek - Altairis, 2016");
            Console.WriteLine(new string('-', Console.WindowWidth - 1));
            Console.WriteLine();

            // Get secret key
            Console.Write("Enter your partner's master symmetric key: ");
            var masterKeyString = Console.ReadLine();
            var masterKey = masterKeyString.FromBase16();
            Console.WriteLine();

            // Get queue
            var q = GetQueue(CONNECTION_STRING, QUEUE_NAME);

            // Main loop
            Console.WriteLine("Enter message to send or empty string to quit:");
            uint messageNumber = 0;
            while (true) {
                // Get message to send
                Console.Write("> ");
                var line = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) break;

                // Increment counter
                messageNumber++;

                // Derive key using NIST SP 800-108 algorithm in counter mode
                var context = BitConverter.GetBytes(messageNumber);
                var derivedKey = new byte[32].AsArraySegment();
                SP800_108_Ctr.DeriveKey(
                    HMACFactories.HMACSHA256, 
                    masterKey, 
                    null, 
                    context.AsArraySegment(), 
                    derivedKey, 
                    messageNumber);

                // Encrypt message
                var encryptedData = SuiteB.Encrypt(derivedKey.Array, line.ToBytes().AsArraySegment());
                var encryptedString = string.Join("|", messageNumber, encryptedData.ToBase16());

                // Prepare and send message
                var msg = new CloudQueueMessage(encryptedString);
                q.AddMessage(msg);

                // Display results
                Console.WriteLine($"< Message #{messageNumber} sent");
            }
            Console.WriteLine("Program terminated successfully");
        }

        static CloudQueue GetQueue(string connectionString, string queueName) {
            if (connectionString == null) throw new ArgumentNullException(nameof(connectionString));
            if (string.IsNullOrWhiteSpace(connectionString)) throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(connectionString));
            if (queueName == null) throw new ArgumentNullException(nameof(queueName));
            if (string.IsNullOrWhiteSpace(queueName)) throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(queueName));

            var account = CloudStorageAccount.Parse(connectionString);
            var qc = account.CreateCloudQueueClient();

            Console.Write($"Connecting to queue {queueName} using {qc.BaseUri.Scheme.ToUpper()}...");
            var q = qc.GetQueueReference(QUEUE_NAME);
            var created = q.CreateIfNotExists();
            Console.WriteLine(created ? "OK, created" : "OK");

            return q;
        }

    }
}
