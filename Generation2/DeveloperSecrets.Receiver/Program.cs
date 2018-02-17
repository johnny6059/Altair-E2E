using System;
using System.Threading;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Queue;
using SecurityDriven.Inferno;
using SecurityDriven.Inferno.Extensions;

namespace DeveloperSecrets.Receiver {
    class Program {
        private const string CONNECTION_STRING = "UseDevelopmentStorage=true";
        private const string QUEUE_NAME = "generation-2";

        static void Main(string[] args) {
            // Set colors to green on black, because everyone knows that's what hackers use
            Console.ForegroundColor = ConsoleColor.Green;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.Clear();

            // Show banner
            Console.WriteLine("Developer Secrets Receiver - Generation 2 (symmetric encryption with single key)");
            Console.WriteLine("Copyright (c) Michal A. Valasek - Altairis, 2016");
            Console.WriteLine(new string('-', Console.WindowWidth - 1));
            Console.WriteLine();

            // Create symmetric key
            var rnd = new CryptoRandom();
            var key = rnd.NextBytes(32);
            var keyString = key.ToBase16();
            Console.WriteLine("This is your symmetric key: " + keyString);
            Console.WriteLine("Send it to your chat partner safely!");
            Console.WriteLine();

            // Get queue
            var q = GetQueue(CONNECTION_STRING, QUEUE_NAME);

            // Main loop
            Console.WriteLine("Waiting for messages. Press SPACEBAR for pause, ESC for exit.");
            Console.WriteLine();

            while (true) {
                // Wait to receive message
                var msg = q.GetMessage();
                if (msg == null) {
                    // No more messages
                    if (Console.KeyAvailable) {
                        var keyCode = Console.ReadKey(intercept: true);
                        if (keyCode.Key == ConsoleKey.Escape) break;
                        if (keyCode.Key == ConsoleKey.Spacebar) {
                            Console.WriteLine();
                            Console.WriteLine("Paused, press any key to continue...");
                            Console.ReadKey(intercept: true);
                            Console.WriteLine("Waiting for messages. Press SPACEBAR for pause, ESC for exit.");
                            Console.WriteLine();
                        }
                    }
                    Thread.Sleep(250);
                    continue;
                }

                // Delete message from queue
                q.DeleteMessage(msg);

                // Authenticate message
                var cipherData = msg.AsString.FromBase16();
                var authenticated = SuiteB.Authenticate(key, cipherData.AsArraySegment());
                if (!authenticated) {
                    Console.WriteLine($"< WARNING!");
                    Console.WriteLine($"< Message {msg.Id} from {msg.InsertionTime:yyyy-MM-dd HH:mm:ss} was tampered with!");
                    continue;
                }

                // Decrypt message
                var plainData = SuiteB.Decrypt(key, cipherData.AsArraySegment());
                var plainString = plainData.FromBytes();

                // Display message
                Console.WriteLine($"< Message {msg.Id} from {msg.InsertionTime:yyyy-MM-dd HH:mm:ss}:");
                Console.WriteLine(plainString);
            }

            Console.WriteLine("Program terminated successfully.");
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
