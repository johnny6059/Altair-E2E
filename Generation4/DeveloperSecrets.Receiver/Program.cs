using System;
using System.Threading;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Queue;
using SecurityDriven.Inferno;
using SecurityDriven.Inferno.Extensions;
using SecurityDriven.Inferno.Kdf;
using SecurityDriven.Inferno.Mac;

namespace DeveloperSecrets.Receiver {
    class Program {
        private const string CONNECTION_STRING = "UseDevelopmentStorage=true";
        private const string QUEUE_NAME = "generation-4";

        static void Main(string[] args) {
            // Set colors to green on black, because everyone knows that's what hackers use
            Console.ForegroundColor = ConsoleColor.Green;
            Console.BackgroundColor = ConsoleColor.Black;
            Console.Clear();

            // Show banner
            Console.WriteLine("Developer Secrets Receiver - Generation 4 (symmetric encryption with asymmetric key exchange)");
            Console.WriteLine("Copyright (c) Michal A. Valasek - Altairis, 2016");
            Console.WriteLine(new string('-', Console.WindowWidth - 1));
            Console.WriteLine();

            // Create asymmetric DHM key pair
            var myKeyPair = CngKeyExtensions.CreateNewDhmKey();
            var myPublicKeyString = myKeyPair.GetPublicBlob().ToBase16();
            Console.WriteLine("This is your public key:");
            Console.WriteLine(myPublicKeyString);
            Console.WriteLine("Send it to your chat partner. The adversary can read the key, but should not be able modify it.");
            Console.WriteLine();

            // Get ephemeral key
            Console.WriteLine("Enter the ephemeral public key:");
            var ephemeralPublicKeyString = Console.ReadLine();
            var ephemeralPublicKey = ephemeralPublicKeyString.FromBase16().ToPublicKeyFromBlob();
            Console.WriteLine();

            // Get shared secret - the master key
            var masterKey = myKeyPair.GetSharedDhmSecret(ephemeralPublicKey);
            Console.WriteLine("This is your master key (displayed for demonstration only):");
            Console.WriteLine(masterKey.ToBase16());
            Console.WriteLine();

            // Delete the original key pair - we don't need it anymore
            myKeyPair.Delete();
            myKeyPair.Dispose();

            // Get queue
            var q = GetQueue(CONNECTION_STRING, QUEUE_NAME);

            // Main loop
            Console.WriteLine("Waiting for messages. Press SPACEBAR for pause, ESC for exit.");
            Console.WriteLine();

            uint expectedMessageNumber = 1;
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

                // Parse message
                var messageParts = msg.AsString.Split('|');
                uint messageNumber = uint.Parse(messageParts[0]);
                var cipherData = messageParts[1].FromBase16();

                // Validate message number
                if (messageNumber < expectedMessageNumber) {
                    // Received number is too low - message is repeated or out of order
                    Console.WriteLine($"WARNING! The following message has too low serial number (expected {expectedMessageNumber}, got {messageNumber}.");
                    Console.WriteLine($"         Message is repeated or was delivered out of order.");
                }
                else if (messageNumber > expectedMessageNumber) {
                    // Received number is too high - some messages are missing or out of order
                    Console.WriteLine($"WARNING! The following message has too high serial number (expected {expectedMessageNumber}, got {messageNumber}.");
                    Console.WriteLine($"         Message was delivered out of order or some messages are missing.");
                    expectedMessageNumber = messageNumber + 1;
                }
                else {
                    // Received number is correct
                    expectedMessageNumber++;
                }

                // Derive key using HKDF algorithm
                var context = BitConverter.GetBytes(messageNumber);
                var derivedKey = new byte[32].AsArraySegment();
                SP800_108_Ctr.DeriveKey(HMACFactories.HMACSHA256, masterKey, null, context.AsArraySegment(), derivedKey, messageNumber);

                // Authenticate message
                var authenticated = SuiteB.Authenticate(derivedKey.Array, cipherData.AsArraySegment());
                if (!authenticated) {
                    Console.WriteLine($"< Message #{messageNumber} ({msg.Id}) from {msg.InsertionTime:yyyy-MM-dd HH:mm:ss} was tampered with!");
                    continue;
                }

                // Decrypt message
                var plainData = SuiteB.Decrypt(derivedKey.Array, cipherData.AsArraySegment());
                var plainString = plainData.FromBytes();

                // Display message
                Console.WriteLine($"< Message #{messageNumber} ({msg.Id}) from {msg.InsertionTime:yyyy-MM-dd HH:mm:ss}:");
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
