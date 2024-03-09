import bodyParser from "body-parser";
import express from "express";
import {BASE_ONION_ROUTER_PORT, REGISTRY_PORT} from "../config";
import {Node} from "../registry/registry";
import {exportPrvKey, exportPubKey, generateRsaKeyPair, rsaDecrypt, symDecrypt} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  let rsaKeyPair = await generateRsaKeyPair();
  let pubKey = await exportPubKey(rsaKeyPair.publicKey);
  let privateKey = rsaKeyPair.privateKey;
  onionRouter.get("/status", (req, res) => {
       res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.status(200).json({result: lastReceivedEncryptedMessage});
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.status(200).json({result: lastReceivedDecryptedMessage});
  });
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.status(200).json({result: lastMessageDestination});
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.status(200).json({result: await exportPrvKey(privateKey)});
  });

  onionRouter.post("/message", async (req, res) => {
    const {message} = req.body;
    const decryptedKey = await rsaDecrypt(message.slice(0, 344), privateKey);
    const decryptedMessage = await symDecrypt(decryptedKey, message.slice(344));

    const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
    const remainingMessage = decryptedMessage.slice(10);
    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;
    await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ message: remainingMessage }),
    });
    res.status(200).send("success");
  });
  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      nodeId: nodeId,
      pubKey: pubKey,
    })
  });


  return server;
}