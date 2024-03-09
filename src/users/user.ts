import bodyParser from "body-parser";
import express from "express";
import {BASE_ONION_ROUTER_PORT, BASE_USER_PORT} from "../config";
import {GetNodeRegistryBody, Node} from "@/src/registry/registry";
import {createRandomSymmetricKey, exportSymKey, importSymKey, rsaEncrypt, symEncrypt} from "../crypto";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

let lastCircuit: Node[] = [];
let lastReceivedMessage: string | null = null;
let lastSentMessage: string | null = null;

export async function user(userId: number) {

  const _user = express();

  _user.use(express.json());
  _user.use(bodyParser.json());

  // TODO implement the status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });




  _user.get("/getLastReceivedMessage", (req, res) => {
    res.status(200).json({result: lastReceivedMessage});
  });

  _user.get("/getLastSentMessage", (req, res) => {
      res.status(200).json({result: lastSentMessage});
  });

  _user.post("/message", (req, res) => {
    lastReceivedMessage = req.body.message;
    res.status(200).send("success");
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.status(200).json({result: lastCircuit.map((node) => node.nodeId)});
  });

  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;

    const nodes = await fetch(`http://localhost:8080/getNodeRegistry`)
        .then((res) => res.json() as Promise<GetNodeRegistryBody>)
        .then((body) => body.nodes);

    let circuit: Node[] = [];
    while (circuit.length < 3) {
      const   randomNode = nodes[Math.floor(Math.random() * nodes.length)];

      if (!circuit.includes(randomNode)) {
        circuit.push(randomNode);
      }
    }

    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
    let finalMessage = message;
    for(const node of circuit) {
      const symmetricKey = await createRandomSymmetricKey();
      const symmetricKey64 = await exportSymKey(symmetricKey);

      const encryptedMessage = await symEncrypt(symmetricKey, `${destination + finalMessage}`);
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, '0');
      const encryptedSymKey = await rsaEncrypt(symmetricKey64, node.pubKey);
      

      finalMessage = encryptedSymKey + encryptedMessage;
    }

    circuit.reverse();
    lastCircuit = circuit;
    lastSentMessage = message;
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: finalMessage }),
    });
    res.status(200).send("success");
  });
  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening${BASE_USER_PORT + userId}`
    );
  });

  return server;
}