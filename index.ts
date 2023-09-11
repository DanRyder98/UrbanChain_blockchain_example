import * as crypto from "crypto";

// When creating a transaction we need two public keys, that from the payer and that from the payee
// In order to make our cryptographic objects easier to work with we serialize them as strings
class Transaction {
    constructor(public amount: number, public payer: string, public payee: string) {}

    toString() {
        return JSON.stringify(this);
    }
}

// A hashing function allows us to take a value of a non-fixed length and convert it to a fixed length
// We provide an input, the hashing function will then generate a hash/digest
// We cannot reverse the process, however we can compare two hash values to see if they are the same
class Block {
    // Used in Chain.mine to make sure two transactions are not added to the chain at the same time
    // This is important because it stops the ability to double spend
    public nonce = Math.round(Math.random() * 999999999);

    constructor(public prevHash: string, public transaction: Transaction, public ts = Date.now()) {}

    // Stringify the object and then use 'secure hash algorithm' included in node.js to generate a hash
    // In this case we are returning a hexadecimal string
    // We have now built a block that is linked to a previous block and contains a transaction and a timestamp
    // so that blocks can be added to the chain in a cronological order
    get hash() {
        const str = JSON.stringify(this);
        const hash = crypto.createHash("SHA256");
        hash.update(str).end();
        return hash.digest("hex");
    }
}

// The chain is a collection of blocks
class Chain {
    // Make sure we have a chain instantiated before we start adding blocks to it
    public static instance = new Chain();

    chain: Block[];

    // Instantiate the chain with a genesis block, transferring 500 coins from the bank to Daniel
    constructor() {
        this.chain = [new Block("", new Transaction(500, "initial", "Daniel"))];
    }

    // Return the last block in the chain
    get lastBlock() {
        return this.chain[this.chain.length - 1];
    }

    // This proves that the chain has not been tampered with
    // We loop through each block in the chain and check that the hash of the previous block matches the prevHash property
    // If the hashes do not match, we know the chain has been tampered with
    // We also check that the hash of the current block is valid
    // If the hashes do not match, we know the chain has been tampered with
    // If the hashes do match, we know the chain is valid
    // This is a very simple example of a proof of work algorithm
    // In a real blockchain, the proof of work algorithm would be much more complex
    // The proof of work algorithm is what makes it computationally expensive to add a block to the chain but also difficult to tamper with
    mine(nonce: number) {
        let solution = 1;
        console.log("mining...");
        // Create new hashes until we find a valid hash starting with '0000'
        while (true) {
            // MD5 is similar to SHA256 but is much faster
            const hash = crypto.createHash("MD5");
            hash.update((nonce + solution).toString()).end();

            const attempt = hash.digest("hex");

            if (attempt.substr(0, 4) === "0000") {
                console.log(`Solved: ${solution}`);
                return solution;
            }

            solution += 1;
        }
    }

    // Add a new block to the chain
    addBlock(transaction: Transaction, senderPublicKey: string, signature: Buffer) {
        // Verify the transaction is valid
        const verifier = crypto.createVerify("SHA256");
        verifier.update(transaction.toString());

        // Verify the transaction is valid
        const isValid = verifier.verify(senderPublicKey, signature);

        // If the transaction is valid, create a new block
        if (isValid) {
            const newBlock = new Block(this.lastBlock.hash, transaction);
            this.chain.push(newBlock);
        }
    }
}

class Wallet {
    public publicKey: string;
    public privateKey: string;

    // RSA can be used to generate a public/private key pair unlike SHA256 which can only generate a hash
    // This allows us to create a digital signature which can be used to verify the authenticity of a transaction
    // The private key is used to sign the transaction and the public key is used to verify the signature
    // Without a signature, anyone could create a transaction and add it to the chain
    // The pem format is a standard format for storing cryptographic objects and would usually be stored in a file on disk
    constructor() {
        const keypair = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

        this.privateKey = keypair.privateKey;
        this.publicKey = keypair.publicKey;
    }

    sendMoney(amount: number, payeePublicKey: string) {
        // Create a new transaction
        const transaction = new Transaction(amount, this.publicKey, payeePublicKey);

        // Create a signature for the transaction
        const sign = crypto.createSign("SHA256");
        sign.update(transaction.toString()).end();

        // Sign the transaction with the private key
        const signature = sign.sign(this.privateKey);

        // Add the transaction to the chain
        Chain.instance.addBlock(transaction, this.publicKey, signature);
    }
}

// Lets now create some wallets and send some money
const daniel = new Wallet();
const josh = new Wallet();
const jacob = new Wallet();

daniel.sendMoney(50, josh.publicKey);
josh.sendMoney(23, jacob.publicKey);
jacob.sendMoney(5, daniel.publicKey);

console.log(Chain.instance);
