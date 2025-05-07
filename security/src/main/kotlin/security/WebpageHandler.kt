package security

import io.vertx.ext.web.handler.BodyHandler
import io.vertx.core.AbstractVerticle
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import org.apache.jena.rdf.model.ModelFactory
import org.apache.jena.rdf.model.Statement
import security.crypto.KeyUtils.generatePrekeys
import security.messages.DecryptedMessage
import java.io.StringReader
import java.nio.ByteBuffer
import java.util.*

class MainVerticle : AbstractVerticle() {
    val users= mutableListOf<User>()

    override fun start() {
        // Initialize Alice and Bob
        users.add(User("alice"))
        users.add(User("bob"))
        users.add(User("carol"))

        for (user in users) {
            for (otherUser in users) {
                if (otherUser.podId != user.podId) {
                    user.preKeysMap[otherUser.podId] = generatePrekeys()
                }
            }
        }

        // Create an HTTP server and router
        val router = Router.router(vertx)
        router.route().handler(BodyHandler.create())

        // Serve the HTML page at the root URL
        router.get("/").handler(this::serveHtmlPage)

        // Define the endpoint to initialize slices schema
        router.post("/initializeSlices").handler(this::initializeSlices)

        // Define the endpoints for X3DH
        router.post("/uploadPreKeys").handler(this::uploadPreKeys)
        router.post("/sendInitialMessage").handler(this::sendInitialMessage)
        router.post("/processInitialMessage").handler(this::processInitialMessage)

        // Define the endpoint to send a message
        router.post("/sendMessage").handler(this::sendMessage)

        //Define the endpoint to retrieve the messages
        router.post("/retrieveMessages").handler(this::retrieveMessages)

        // Create the HTTP server
        vertx.createHttpServer()
            .requestHandler(router)
            .listen(12000) { result ->
                if (result.succeeded()) {
                    println("Server started on port 12000")
                } else {
                    println("Failed to start server: ${result.cause()}")
                }
            }
    }

    // Function to serve the HTML page
    private fun serveHtmlPage(ctx: RoutingContext) {
        val html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Communication Pod Example</title>
                <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                }
                .container {
                    width: 80%;
                    display: flex;
                    flex-direction: column;
                    gap: 20px;
                }
                .top-section {
                    text-align: center;
                }
                .input-container {
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }
                .message-section {
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                }
                .inbox {
                    border: 1px solid #ccc;
                    padding: 10px;
                    min-height: 100px;
                    background-color: #f9f9f9;
                    overflow-y: auto;
                }
                .grid-container {
                    display: grid;
                    grid-template-columns: auto auto;
                }
                .grid-item {
                    height: 100px;
                    resize: none;
                }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="top-section">
                        <h1>Communication Pod</h1>
                        <label for="podName">Enter Target Pod Name:</label>
                        <input type="text" id="sender" placeholder="Sender">
                        <input type="text" id="authCode" placeholder="Authorization Code">
                        <input type="text" id="stepInitiator" placeholder="stepInitiator">
                    </div>
                    <div class="top-section">
                        <button onclick="initializeSlices()">Initialize Slices</button>
                        <button onclick="uploadPreKeys()">Upload PreKeys</button>
                        <button onclick="sendInitialMessage()">Send Initial Message</button>
                        <button onclick="processInitialMessage()">Process Initial Message</button>
                    </div>
                    <div class="top-section">
                        <input type="checkbox" id="keepStructure">
                        <label for="keepStructure">Keep Structure</label>
                    </div>
                    <div class="grid-container">
                        <div class="grid-item">
                            <h3>Values that should be encrypted (uri's with prefix)</h3>
                            <textarea id="valuesToEncryptString" rows="7" cols="40"></textarea>
                        </div>
                        <div class="grid-item">
                            <h3>Groups of triples that should be encrypted</h3>
                            <textarea id="tripleGroupsToEncryptString" rows="7" cols="40"></textarea>
                        </div>
                    </div>

    
                    <div class="input-container">
                        <div>
                            <h2>Alice's Messages</h2>
                            <textarea id="aliceMessage" placeholder="Enter Alice's message"></textarea>
                            <button onclick="sendMessage('alice')">Send</button>
                        </div>
                        <div>
                            <h2>Bob's Messages</h2>
                            <textarea id="bobMessage" placeholder="Enter Bob's message"></textarea>
                            <button onclick="sendMessage('bob')">Send</button>
                        </div>
                        <div>
                            <h2>Carol's Messages</h2>
                            <textarea id="carolMessage" placeholder="Enter Carol's message"></textarea>
                            <button onclick="sendMessage('carol')">Send</button>
                        </div>
                    </div>
    
                    <div class="inbox-container">
                        <div>
                            <h2>Alice's Inbox</h2>
                            <button onclick="retrieveMessages('alice')">Retrieve Messages</button>
                            <div id="aliceInbox" class="inbox"></div>
                        </div>
                        <div>
                            <h2>Bob's Inbox</h2>
                            <button onclick="retrieveMessages('bob')">Retrieve Messages</button>
                            <div id="bobInbox" class="inbox"></div>
                        </div>
                         <div>
                            <h2>Carol's Inbox</h2>
                            <button onclick="retrieveMessages('carol')">Retrieve Messages</button>
                            <div id="carolInbox" class="inbox"></div>
                        </div>
                    </div>
                </div>

                <script>
                    let podId = 'alicebob'
                    let authCode = ''
                    let inboxes = {};
                    
                    function initializeSlices() {
                        authCode = document.getElementById('authCode').value
                        
                        fetch('/initializeSlices', {
                            method: 'POST',
                            headers: {
                               'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                podId: podId,
                                authCode: authCode
                            }),
                        })
                        .then(response => response.json())
                        .then(data => {
                             alert(data.message);
                        })
                        .catch(err => console.error('Error:', err));
                    }
                    
                    function uploadPreKeys() {
                        let stepInitiator = document.getElementById('stepInitiator').value;
                        fetch('/uploadPreKeys', {
                            method: 'POST',
                            headers: {
                            'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                podId: podId,
                                authCode: authCode,
                                stepInitiator: stepInitiator
                            }),
                        })
                        .then(response => response.json())
                        .then(data => alert(data.message))
                        .catch(err => console.error('Error:', err));
                    }
                    
                    function sendInitialMessage() {
                        let stepInitiator = document.getElementById('stepInitiator').value;
                        fetch('/sendInitialMessage', {
                            method: 'POST',
                            headers: {
                               'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                podId: podId,
                                authCode: authCode,
                                stepInitiator: stepInitiator
                            }),
                        })
                        .then(response => response.json())
                        .then(data => alert(data.message))
                        .catch(err => console.error('Error:', err));
                    }
                    function processInitialMessage() {
                        let stepInitiator = document.getElementById('stepInitiator').value;
                        fetch('/processInitialMessage', {
                            method: 'POST',
                            headers: {
                               'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                podId: podId,
                                authCode: authCode,
                                stepInitiator: stepInitiator
                            }),
                        })
                        .then(response => response.json())
                        .then(data => alert(data.message))
                        .catch(err => console.error('Error:', err));
                    }

                    function sendMessage(sender) {                        
                        const message = document.getElementById(sender + 'Message').value
                        
                        const keepStructure = document.getElementById('keepStructure').checked ? "true" : "false";
                        const valuesToEncryptString = document.getElementById('valuesToEncryptString').value;
                        const tripleGroupsToEncryptString = document.getElementById('tripleGroupsToEncryptString').value;

                        

                        if (message) {
                            const timestamp = Date.now();
                            
                            if (!inboxes[sender]) {
                                inboxes[sender] = [];
                            }
                            
                            inboxes[sender].push({
                                sender: sender,
                                content: message,
                                timestamp: timestamp
                            });
                            
                            fetch('/sendMessage', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({
                                        podId: podId,
                                        authCode: authCode,
                                        sender: sender,
                                        message: message,
                                        timestamp: timestamp,
                                        keepStructure: keepStructure,
                                        valuesToEncryptString: valuesToEncryptString,
                                        tripleGroupsToEncryptString: tripleGroupsToEncryptString
                                    }),
                                })
                                .then(response => response.json())
                                .then(data => {
                                    alert(data);
                                    
                                    document.getElementById('aliceMessage').value = ''; // Clear Alice's input field
                                    document.getElementById('bobMessage').value = ''; // Clear Bob's input field
                                    document.getElementById('carolMessage').value = ''; // Clear Bob's input field
                                   
                                    // add to own inbox
                                    const inbox = document.getElementById(sender + 'Inbox')
                                    
                                    let msgElement = document.createElement("p");
                                    msgElement.innerHTML = "<strong>" + sender.charAt(0).toUpperCase() + sender.slice(1) + ":</strong> " + message + ', ' + timestamp;
                                    
                                    // Append the new message at the bottom of the inbox
                                    inbox.appendChild(msgElement);
                                })
                                .catch(err => console.error('Error:', err));
                        } else {
                            alert('Please enter a message!');
                        }
                    }
                    
                    function retrieveMessages(user) {
                        const keepStructure = document.getElementById('keepStructure').checked ? "true" : "false";
                        
                        fetch('/retrieveMessages', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({
                                    podId: podId,
                                    authCode: authCode,
                                    receiverPodId: user,
                                    keepStructure: keepStructure
                                }),
                            })
                            .then(response => response.json())
                            .then(data => {
                                console.log(data)
                                const receiver = user
                                
                                if (!inboxes[receiver]) {
                                    inboxes[receiver] = [];
                                }
                                
                                const inbox = inboxes[receiver];

                                Object.entries(data.messages).forEach(([sender, msgList]) => {
                                    msgList.forEach(msg => {
                                        const plainText = msg.plainText;
                                        const timestamp = msg.timestamp;
                                
                                        inbox.push({ sender, content: plainText, timestamp });
                                    });
                                });
                                
                                displayMessages(receiver)
                            })
                            .catch(err => console.error('Error:', err));
                    }
                    
                    function displayMessages(receiver) {
                        const messages = inboxes[receiver]
                        const inbox = document.getElementById(receiver + 'Inbox')
                        
                        inbox.innerHTML = '';
                        messages.sort((a,b) => a.timestamp - b.timestamp);
                        
                        for (let i = 0; i<messages.length; i++) {
                            let msgElement = document.createElement("p");
                            msgElement.innerHTML = "<strong>" + messages[i].sender.charAt(0).toUpperCase() + messages[i].sender.slice(1) + ":</strong> " + messages[i].content + ', ' + messages[i].timestamp;
                            inbox.appendChild(msgElement);
                        }
                    }
                </script>
            </body>
            </html>
        """
        ctx.response()
            .putHeader("Content-Type", "text/html")
            .end(html)
    }

    /*
        Initialize the slices schema for the PreKeys and the InitialMessage
     */
    private fun initializeSlices(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val podId = jsonBody.getString("podId")
        val authCode = jsonBody.getString("authCode")

        try {
            X3DH.initiateSliceSchema(podId, authCode)
        }
        catch (e: Exception) {
            println(e)
        }
            // Placeholder for initializing slices schema
        ctx.response()
            .putHeader("Content-Type", "application/json")
            .end("{\"message\": \"Initiate slices to targetpods\"}")

    }

    /*
        Upload the new PreKeys
     */
    private fun uploadPreKeys(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val podId = jsonBody.getString("podId")
        val authCode = jsonBody.getString("authCode")
        val stepInitiator = jsonBody.getString("stepInitiator")

        val index = users.indexOfFirst { it.podId == stepInitiator }
        println("step upload: $stepInitiator")
        println("users upload: $users")

        for (i in users.indices) {
            if (i != index) {
                val keysId = if (users[i].podId <= stepInitiator) users[i].podId + stepInitiator else stepInitiator + users[i].podId
                println("keysId upload: $keysId")

                X3DH.uploadPreKeys(podId, users.get(i).preKeysMap.get(stepInitiator)!!.getPublic(), keysId, authCode)
            }
        }


        ctx.response().putHeader("Content-Type", "application/json")
            .end("{\"message\": \"PreKeys uploaded for targetPodIds\"}")

    }

    /*
        Send the initial message
     */
    private fun sendInitialMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val podId = jsonBody.getString("podId")
        val authCode = jsonBody.getString("authCode")
        val stepInitiator = jsonBody.getString("stepInitiator")

        val index = users.indexOfFirst { it.podId == stepInitiator }

        println("step initial: $stepInitiator")

        for (i in users.indices) {
            if (i != index && !users.get(index).sharedKeysMap.containsKey(users.get(i).podId)) {
                val initiator = users.get(index)
                val otherParty = users.get(i)
                val keysId = if (otherParty.podId <= stepInitiator) otherParty.podId + stepInitiator else stepInitiator + otherParty.podId

                println("keysId initial: $keysId")

                initiator.sharedKeysMap.put(otherParty.podId, X3DH.sendInitialMessage(users.get(index), podId, initiator.preKeysMap.get(otherParty.podId)!!, otherParty.podId, keysId, authCode))
            }
        }

        ctx.response().putHeader("Content-Type", "application/json")
            .end("{\"message\": \"Initial message sent for targetPodIds\"}")
    }

    /*
        Process the initial message
     */
    private fun processInitialMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val podId = jsonBody.getString("podId")
        val authCode = jsonBody.getString("authCode")
        val stepInitiator = jsonBody.getString("stepInitiator")

        val index = users.indexOfFirst { it.podId == stepInitiator }

        println("step process: $stepInitiator")

        try {
            for (i in users.indices) {
                if (i != index && !users.get(i).sharedKeysMap.containsKey(users.get(index).podId)) {
                    val initiator = users.get(index)
                    val otherParty = users.get(i)
                    val keysId = if (otherParty.podId <= stepInitiator) otherParty.podId + stepInitiator else stepInitiator + otherParty.podId

                    println("keysId process: $keysId")

                    otherParty.sharedKeysMap.put(initiator.podId, X3DH.processInitialMessage(otherParty, podId, otherParty.preKeysMap.get(initiator.podId)!!, initiator.podId, keysId, authCode))
                }
            }
        }
        catch (e: Exception) {
            println("errorare: $e")
            throw RuntimeException(e)
        }

        ctx.response().putHeader("Content-Type", "application/json")
            .end("{\"message\": \"Initial message processed for targetPodIds\"}")

    }

    /*
        Send a new message
     */

    private fun sendMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val podId = jsonBody.getString("podId")
        val authCode = jsonBody.getString("authCode")

        val senderPodId = jsonBody.getString("sender")
        val index = users.indexOfFirst { it.podId == senderPodId }

        println("person wwwho sends: $senderPodId")

        val message = jsonBody.getString("message")

        val timestampString = jsonBody.getString("timestamp")
        val timestampBytes = ByteBuffer.allocate(8).putLong(timestampString.toLong()).array()

        val keepStructureParam = jsonBody.getString("keepStructure")
        val keepStructure = keepStructureParam != null && keepStructureParam == "true"

        val valuesToEncryptString = jsonBody.getString("valuesToEncryptString")
        val tripleGroupsToEncryptString = jsonBody.getString("tripleGroupsToEncryptString")

        val encryptionLists = if (keepStructure) processEncryptionLists(valuesToEncryptString, tripleGroupsToEncryptString) else Pair(emptyList(), emptyList())
        val valuesToEncrypt = encryptionLists.first
        val tripleGroupsToEncrypt = encryptionLists.second

        for (user in users) {
            println(user.sharedKeysMap)
        }

        try{
            for (i in users.indices) {
                if (users[i].podId != senderPodId) {
                    val sender = users.get(index)
                    val otherParty = users.get(i)

                    println("sent to user: ${users.get(i)}")

                    if (sender.sendingKeyMap.isEmpty() || !sender.sendingKeyMap.containsKey(otherParty.podId)) {
                        sender.sendInitialMessage(podId, message.toByteArray(), timestampBytes, otherParty.podId, authCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt)
                    }
                    else {
                        sender.sendMessage(podId, message.toByteArray(), timestampBytes, otherParty.podId, authCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt)
                    }
                }
            }
        }
        catch (e: Exception) {
            println(e)
            throw RuntimeException(e)
        }
        val jsonResponse = JsonObject()
            .put("message", "Message sent to targetPodIds pod")
        ctx.response()
            .putHeader("Content-Type", "application/json")
            .end(jsonResponse.encode())
    }

    private fun processEncryptionLists(valuesToEncryptString: String, tripleGroupsToEncryptString: String): Pair<List<String>, List<List<Statement>>> {
        val valuesToEncryptModel = ModelFactory.createDefaultModel()
        val groupsToEncryptModel = ModelFactory.createDefaultModel()

        try {
            valuesToEncryptModel.read(StringReader(valuesToEncryptString), null, "JSON-LD")
            groupsToEncryptModel.read(StringReader(tripleGroupsToEncryptString), null, "JSON-LD")
        }
        catch (e: Exception) {
            throw Error("No valid json was provided")
        }
        val encryptionConfigRes = valuesToEncryptModel.getResource("http://example.org/encryptionValues")
        val propertyToEncrypt = valuesToEncryptModel.getProperty("http://example.org/valuesToEncrypt")

        val valuesToEncryptList = valuesToEncryptModel.listObjectsOfProperty(encryptionConfigRes, propertyToEncrypt)
            .toList()
            .map { it.asResource().uri }



        val tripleGroupsToEncrypt = groupsToEncryptModel.listStatements().toList()
            .groupBy { it.subject }
            .values.toList()

        return Pair(valuesToEncryptList, tripleGroupsToEncrypt)
    }

    /*
        Retrieve new messages
     */
    private fun retrieveMessages(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        ///// return sender

        try {
            val podId = jsonBody.getString("podId")
            val authCode = jsonBody.getString("authCode")

            val receiverPodId = jsonBody.getString("receiverPodId")
            val index = users.indexOfFirst { it.podId == receiverPodId }

            val keepStructureParam = jsonBody.getString("keepStructure")
            val keepStructure = keepStructureParam != null && keepStructureParam == "true"

            var messages = mutableMapOf<String, MutableList<DecryptedMessage>>()
            for (i in users.indices) {
                if (users[i].podId != receiverPodId) {
                    messages.getOrPut(users[i].podId) { mutableListOf() }.addAll(users.get(index).receiveMessage(podId, users[i].podId, authCode, keepStructure))
                }
            }

            val messagesJson = JsonObject()

            for ((sender, msgList) in messages) {
                val msgArray = msgList.map { msg ->
                    JsonObject()
                        .put("plainText", msg.plainText)
                        .put("timestamp", msg.timestamp)
                }
                messagesJson.put(sender, msgArray)
            }

            val jsonResponse = JsonObject().put("messages", messagesJson)

            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end(jsonResponse.encode())
        }
        catch (e: Exception) {
            println(e)
            throw RuntimeException(e)
        }
    }
}