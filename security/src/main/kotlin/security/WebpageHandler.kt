package security

import io.vertx.ext.web.handler.BodyHandler
import io.vertx.core.AbstractVerticle
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import org.apache.jena.rdf.model.ModelFactory
import org.apache.jena.rdf.model.Statement
import security.crypto.generatePrekeys
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
                user.preKeysMap[otherUser.podId] = generatePrekeys()
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
                        <input type="text" id="authCodealice" placeholder="Authorization Code">
                        <input type="text" id="authCodebob" placeholder="Authorization Code">
                        <input type="text" id="authCodecarol" placeholder="Authorization Code">
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
                    let sender = '';
                    let pods = ['alice', 'bob', 'carol'];
                    let inboxes = {};
                    
                    function initializeSlices() {
                        const authCodes = [document.getElementById('authCodealice').value, document.getElementById('authCodebob').value, document.getElementById('authCodecarol').value];
                        
                        fetch('/initializeSlices', {
                            method: 'POST',
                            headers: {
                               'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                pods: pods,
                                authCodes: authCodes
                            }),
                        })
                        .then(response => response.json())
                        .then(data => {
                             alert(data.message);
                        })
                        .catch(err => console.error('Error:', err));
                    }
                    
                    function uploadPreKeys() {
                        const authCodes = [document.getElementById('authCodealice').value, document.getElementById('authCodebob').value, document.getElementById('authCodecarol').value];
                        fetch('/uploadPreKeys', {
                            method: 'POST',
                            headers: {
                            'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                pods: pods,
                                authCodes: authCodes
                            }),
                        })
                        .then(response => response.json())
                        .then(data => alert(data.message))
                        .catch(err => console.error('Error:', err));
                    }
                    
                    function sendInitialMessage() {
                        const authCodes = [document.getElementById('authCodealice').value, document.getElementById('authCodebob').value, document.getElementById('authCodecarol').value];
                        sender = document.getElementById('sender').value;
                        let podParam = encodeURIComponent(pods.join(','));
                        let authParam = encodeURIComponent(authCodes.join(','));
                        fetch('/sendInitialMessage', {
                            method: 'POST',
                            headers: {
                               'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                pods: pods,
                                authCodes: authCodes,
                                sender: sender
                            }),
                        })
                        .then(response => response.json())
                        .then(data => alert(data.message))
                        .catch(err => console.error('Error:', err));
                    }
                    function processInitialMessage() {
                        const authCodes = [document.getElementById('authCodealice').value, document.getElementById('authCodebob').value, document.getElementById('authCodecarol').value];
                        let podParam = encodeURIComponent(pods.join(','));
                        let authParam = encodeURIComponent(authCodes.join(','));
                        fetch('/processInitialMessage', {
                            method: 'POST',
                            headers: {
                               'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                pods: pods,
                                authCodes: authCodes,
                                sender: sender
                            }),
                        })
                        .then(response => response.json())
                        .then(data => alert(data.message))
                        .catch(err => console.error('Error:', err));
                    }

                    function sendMessage(sender) {
                        const authCodes = [document.getElementById('authCodealice').value, document.getElementById('authCodebob').value, document.getElementById('authCodecarol').value];
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
                                        pods: pods,
                                        sender: sender,
                                        message: message,
                                        timestamp: timestamp,
                                        authCodes: authCodes,
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
                        const authCodes = [document.getElementById('authCodealice').value, document.getElementById('authCodebob').value, document.getElementById('authCodecarol').value];
                        const keepStructure = document.getElementById('keepStructure').checked ? "true" : "false";
                        
                        fetch('/retrieveMessages', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({
                                    pods: pods,
                                    user: user,
                                    authCodes: authCodes,
                                    keepStructure: keepStructure
                                }),
                            })
                            .then(response => response.json())
                            .then(data => {
                                console.log(data)
                                const receiver = user
                                const sender = data.sender
                                
                                if (!inboxes[receiver]) {
                                    inboxes[receiver] = [];
                                }
                                
                                const inbox = inboxes[receiver];

                                data.messages.forEach(msg => {
                                    const plainText = msg.plainText
                                    const timestamp = msg.timestamp
                                                                        
                                    inbox.push({sender: sender, content: plainText, timestamp: timestamp})
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

        val targetPodIds = jsonBody.getJsonArray("pods")
        val authCodes = jsonBody.getJsonArray("authCodes")

        try {
            for (i in 0..targetPodIds.size() - 1) {
                X3DH.initiateSliceSchema(targetPodIds.getString(i), authCodes.getString(i))
            }
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

        val targetPodIds = jsonBody.getJsonArray("pods")
        val authCodes = jsonBody.getJsonArray("authCodes")

        println(targetPodIds)
        println(authCodes)
        println(users)



        for (i in 0..targetPodIds.size() - 1) {
            X3DH.uploadPreKeys(targetPodIds.getString(i), users.get(i).preKeysMap.get(targetPodIds.getString(i))!!.getPublic(), authCodes.getString(i))
        }


        ctx.response().putHeader("Content-Type", "application/json")
            .end("{\"message\": \"PreKeys uploaded for targetPodIds\"}")

    }

    /*
        Send the initial message
     */
    private fun sendInitialMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val targetPodIds = jsonBody.getJsonArray("pods")
        val authCodes = jsonBody.getJsonArray("authCodes")
        val sender = jsonBody.getString("sender")
        val senderIndex = targetPodIds.indexOf(sender)

        try {
            for (i in 0 until targetPodIds.size()) {
                println(users.get(senderIndex).preKeysMap)
                if (!targetPodIds.getString(i).equals(sender) && !users.get(senderIndex).sharedKeysMap.containsKey(targetPodIds.getString(i))) {
                    users.get(senderIndex).sharedKeysMap.put(targetPodIds.getString(i), X3DH.sendInitialMessage(users.get(senderIndex), targetPodIds.getString(i), users.get(senderIndex).preKeysMap.get(targetPodIds.getString(i))!!, authCodes.getString(i)))
                }
            }
        }
        catch (e: Exception) {
            println(e)
        }

        ctx.response().putHeader("Content-Type", "application/json")
            .end("{\"message\": \"Initial message sent for targetPodIds\"}")
    }

    /*
        Process the initial message
     */
    private fun processInitialMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val targetPodIds = jsonBody.getJsonArray("pods")
        val authCodes = jsonBody.getJsonArray("authCodes")
        val sender = jsonBody.getString("sender")
        val senderIndex = targetPodIds.indexOf(sender)

        println(targetPodIds.size())

        try {
            for (i in 0 until targetPodIds.size()) {
                println(targetPodIds.getString(i))
                println("a: " + users.get(senderIndex).sharedKeysMap)
                if (!targetPodIds.getString(i).equals(sender) && !users.get(i).sharedKeysMap.containsKey(targetPodIds.getString(senderIndex))) {
                    users.get(i).sharedKeysMap.put(sender, X3DH.processInitialMessage(users.get(i), targetPodIds.getString(i), users.get(i).preKeysMap.get(targetPodIds.getString(i))!!, authCodes.getString(i), sender))
                }
            }
        }
        catch (e: Exception) {
            println(e)
        }


        ctx.response().putHeader("Content-Type", "application/json")
            .end("{\"message\": \"Initial message processed for targetPodIds\"}")

    }

    /*
        Send a new message
     */

    private fun sendMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val targetPodIds = jsonBody.getJsonArray("pods")
        val sender = jsonBody.getString("sender")
        val message = jsonBody.getString("message")
        val timestampString = jsonBody.getString("timestamp")
        val timestampBytes = ByteBuffer.allocate(8).putLong(timestampString.toLong()).array()
        val authCodes = jsonBody.getJsonArray("authCodes")
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
            for (user in users) {
                if (user.podId != sender) {
                    val senderIndex = targetPodIds.indexOf(sender)
                    if (users.get(senderIndex).sendingKeyMap.isEmpty() || !users.get(senderIndex).sendingKeyMap.containsKey(user.podId)) {
                        users.get(senderIndex).sendInitialMessage(user.podId, message.toByteArray(), timestampBytes, authCodes.getString(targetPodIds.indexOf(user.podId)), keepStructure, valuesToEncrypt, tripleGroupsToEncrypt)
                    }
                    else {
                        users.get(senderIndex).sendInitialMessage(user.podId, message.toByteArray(), timestampBytes, authCodes.getString(targetPodIds.indexOf(user.podId)), keepStructure, valuesToEncrypt, tripleGroupsToEncrypt)
                    }
                }
            }
        }
        catch (e: Exception) {
            println(e)
        }
        val jsonResponse = JsonObject()
            .put("message", "Message sent from $sender to targetPodIds pod")
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

        val targetPodIds = jsonBody.getJsonArray("pods")
        val user = jsonBody.getString("user")
        val userIndex = targetPodIds.indexOf(user)
        val authCodes = jsonBody.getJsonArray("authCodes")
        val keepStructureParam = jsonBody.getString("keepStructure")
        val keepStructure = keepStructureParam != null && keepStructureParam == "true"

        println(users.get(1).targetPublicKeyMap)

        for (target in users) {
            if (target.podId != user) {
                try {
                    val messages = users.get(userIndex).receiveMessage(target.podId, authCodes.getString(userIndex), keepStructure)

                    val jsonResponse = JsonObject().put("messages", messages).put("sender", target.podId)

                    ctx.response()
                        .putHeader("Content-Type", "application/json")
                        .end(jsonResponse.encode())
                    break
                }
                catch (e: Exception) {
                    println(e)
                    continue
                }
            }
        }
    }
}