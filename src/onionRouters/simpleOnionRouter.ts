import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey, exportPubKey, symDecrypt, rsaDecrypt, importPrvKey } from '../crypto';
import http, { IncomingMessage, RequestOptions } from "http";

type MessageBody = {
  encryptedMessage: string;
};

let lastReceivedEncryptedMessage: string | null = null;
let lastReceivedDecryptedMessage: string | null = null;
let lastMessageDestination: number | null = null;
let privateKey: string | null = null;
let publicKey: string | null = null;

async function registerNode(nodeId: number) {
  const { privateKey: generatedPrivateKey, publicKey: generatedPublicKey } = await generateRsaKeyPair();
  privateKey = await exportPrvKey(generatedPrivateKey);
  publicKey = await exportPubKey(generatedPublicKey)

  const postData = JSON.stringify({ nodeId, pubKey: publicKey });
  const options = {
    hostname: "localhost",
    port: REGISTRY_PORT,
    path: "/registerNode",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": postData.length
    }
  };

  const httpRequest = http.request(options, (response) => {
    console.log(`Node ${nodeId} registered successfully.`);
  });

  httpRequest.on("error", (error) => {
    console.error(`Error registering node ${nodeId} on startup:`, error);
  });

  httpRequest.write(postData);
  httpRequest.end();
}

async function handleMessage(req: { body: MessageBody; }, res: { json: any; status: any; }) {
  const { encryptedMessage }: MessageBody = req.body;

  if (privateKey !== null) {
    const [encryptedSymmetricKey, encryptedLayer1] = [
      encryptedMessage.slice(0, 44),
      encryptedMessage.slice(44)
    ];

    const decryptedSymmetricKey = await rsaDecrypt(encryptedSymmetricKey, await importPrvKey(privateKey));
    const decryptedMessageWithDestination = await symDecrypt(decryptedSymmetricKey, encryptedLayer1);
    const decryptedMessage = decryptedMessageWithDestination.slice(0, -10);
    const destination = decryptedMessageWithDestination.slice(-10);

    if (destination) {
      forwardMessage(destination, encryptedMessage, res);
    } else {
      res.json({ message: "Message delivered to destination user." });
    }
  } else {
    console.error("Private key is null.");
    res.status(500).json({ error: "Private key is null." });
  }
}

function forwardMessage(destination: string, encryptedMessage: string, res: { json: (arg0: { message: string; }) => void; status: (arg0: number) => { (): any; new(): any; json: { (arg0: { error: string; }): void; new(): any; }; }; }) {
  const postData = JSON.stringify({ encryptedMessage });
  const options: RequestOptions = {
    hostname: "localhost",
    port: destination,
    path: "/message",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData)
    }
  };

  const httpRequest = http.request(options, (response: IncomingMessage) => {
    res.json({ message: "Message forwarded successfully." });
  });

  httpRequest.on("error", (error) => {
    console.error("Error sending HTTP request:", error);
    res.status(500).json({ error: "Internal server error." });
  });

  httpRequest.write(postData);
  httpRequest.end();
}

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  onionRouter.get("/status", (req, res) => { res.send("live");});
  onionRouter.post("/message", handleMessage);
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => { res.json({ result: lastReceivedEncryptedMessage }); });
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => { res.json({ result: lastReceivedDecryptedMessage }); });
  onionRouter.get("/getLastMessageDestination", (req, res) => { res.json({ result: lastMessageDestination }); });
  onionRouter.get("/getPrivateKey", (req, res) => {
    if (privateKey !== null) {
      res.json({ result: privateKey });
    } else {
      res.status(500).json({ error: "Private key not available" });
    }
  });

  try {
    await registerNode(nodeId);
  } catch (error) {
    console.error(`Error registering node ${nodeId} on startup:`, error);
  }

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}