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

class MainVerticle : AbstractVerticle() {
    val Alice = User("alice")
    val Bob = User("bob")
    var isNotInitialized = true
    val mocked = false

    override fun start() {
        // Initialize Alice and Bob
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()


        // Create an HTTP server and router
        val router = Router.router(vertx)
        router.route().handler(BodyHandler.create())

        // Serve the HTML page at the root URL
        router.get("/").handler(this::serveHtmlPage)

        // Endpoint to generate new PreKeys
        router.get("/generatePreKeys").handler(this::generatePreKeys)

        // Define the endpoint to initialize slices schema
        router.get("/initializeSlices").handler(this::initializeSlices)

        // Define the endpoints for X3DH
        router.get("/uploadPreKeys").handler(this::uploadPreKeys)
        router.get("/sendInitialMessage").handler(this::sendInitialMessage)
        router.get("/processInitialMessage").handler(this::processInitialMessage)

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
                    <div>
                        <button onclick="generatePreKeys('alice')">Generate Alice's PreKeys</button>
                        <button onclick="generatePreKeys('bob')">Generate Bob's PreKeys</button>
                    </div>
                    <div class="top-section">
                        <h1>Communication Pod</h1>
                        <label for="podName">Enter Target Pod Name:</label>
                        <input type="text" id="podName" placeholder="Pod Name">
                        <input type="text" id="authCode" placeholder="Authorization Code">
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
                        <input type="checkbox" id="groupMessage">
                        <label for="groupMessage">Send Group Message</label>
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
                    </div>
    
                    <div class="inbox-container">
                        <div>
                            <h3>Encryption message that was send</h3>
                            <div id="encryptedMessage" class="inbox"></div>
                        </div>
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
                    </div>
                </div>

                <script>
                    let aliceInbox = [];
                    let bobInbox = [];
                    let podName = '';
                    
                    function generatePreKeys(user) {
                        fetch('/generatePreKeys?user=' + user)
                            .then(response => response.json())
                            .then(data => alert(data.message))
                            .catch(err => console.error('Error:', err));
                    }
                    
                    function initializeSlices() {
                        podName = document.getElementById('podName').value;
                        let authCode = document.getElementById('authCode').value;
                        if (podName && authCode) {
                            fetch('/initializeSlices?pod=' + podName + '&authCode=' + authCode)
                                .then(response => response.json())
                                .then(data => {
                                    alert(data.message);
                                })
                                .catch(err => console.error('Error:', err));
                        } else {
                            alert('Please enter both Pod Name and Authorization Code!');
                        }
                    }
                    
                    function uploadPreKeys() {
                        podName = document.getElementById('podName').value;
                        let authCode = document.getElementById('authCode').value;
                        fetch('/uploadPreKeys?pod=' + podName + '&authCode=' + authCode)
                            .then(response => response.json())
                            .then(data => alert(data.message))
                            .catch(err => console.error('Error:', err));
                    }
                    function sendInitialMessage() {
                        podName = document.getElementById('podName').value;
                        let authCode = document.getElementById('authCode').value;
                        fetch('/sendInitialMessage?pod=' + podName + '&authCode=' + authCode)
                            .then(response => response.json())
                            .then(data => alert(data.message))
                            .catch(err => console.error('Error:', err));
                    }
                    function processInitialMessage() {
                        podName = document.getElementById('podName').value;
                        let authCode = document.getElementById('authCode').value;
                        fetch('/processInitialMessage?pod=' + podName + '&authCode=' + authCode)
                            .then(response => response.json())
                            .then(data => alert(data.message))
                            .catch(err => console.error('Error:', err));
                    }

                    function sendMessage(sender) {
                        const message = sender === 'alice' ? document.getElementById('aliceMessage').value : document.getElementById('bobMessage').value;
                        let authCode = document.getElementById('authCode').value;
                        const keepStructure = document.getElementById('keepStructure').checked ? "true" : "false";
                        const valuesToEncryptString = document.getElementById('valuesToEncryptString').value;
                        const tripleGroupsToEncryptString = document.getElementById('tripleGroupsToEncryptString').value;


                        if (message) {
                            const timestamp = Date.now();
                            
                            if (sender === 'alice') {
                                aliceInbox.push({ sender: sender, content: message, timestamp: timestamp });
                            } else {
                                bobInbox.push({ sender: sender, content: message, timestamp: timestamp });
                            }
                            
                            fetch('/sendMessage', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({
                                        pod: podName,
                                        sender: sender,
                                        message: message,
                                        timestamp: timestamp,
                                        authCode: authCode,
                                        keepStructure: keepStructure,
                                        valuesToEncryptString: valuesToEncryptString,
                                        tripleGroupsToEncryptString: tripleGroupsToEncryptString
                                    }),
                                })
                                .then(response => response.json())
                                .then(data => {
                                    alert(data);
                                    
                                    let encbox = document.getElementById('encryptedMessage');
                                    encbox.innerHTML = '';
                                     
                                    if (keepStructure == "true") {
                                        let encmsgElement = document.createElement("p");
                                        encmsgElement.innerHTML = data.encryptedMessage;
                                        encbox.appendChild(encmsgElement);
                                    }
                                    
                                    if (sender === 'alice') {
                                        document.getElementById('aliceMessage').value = ''; // Clear Alice's input field
                                    } else {
                                        document.getElementById('bobMessage').value = ''; // Clear Bob's input field
                                    }
                                    // add to own inbox
                                    const inbox = sender === 'alice' ? document.getElementById('aliceInbox') : document.getElementById('bobInbox');
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
                        let authCode = document.getElementById('authCode').value;
                        const keepStructure = document.getElementById('keepStructure').checked ? "true" : "false";
                        
                        fetch('/retrieveMessages', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({
                                    pod: podName,
                                    user: user,
                                    authCode: authCode,
                                    keepStructure: keepStructure
                                }),
                            })
                            .then(response => response.json())
                            .then(data => {
                                const inbox = user === 'alice' ? aliceInbox : bobInbox;
                                const receiver = user === "alice" ? "alice" : "bob";
                                const sender = user === 'alice' ? 'bob' : 'alice';

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
                        const messages = receiver === 'alice' ? aliceInbox : bobInbox
                        const inbox = receiver === 'alice' ? document.getElementById('aliceInbox') : document.getElementById('bobInbox');
                        
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
        Generate new PreKeys
     */
    private fun generatePreKeys(ctx: RoutingContext) {
        val user = ctx.request().getParam("user")

        if (user == "alice") {
            Alice.preKeys = generatePrekeys()
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"New prekeys generated for Alice\"}")
        } else if (user == "bob") {
            Bob.preKeys = generatePrekeys()
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"New prekeys generated for Bob\"}")
        } else {
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Invalid user!\"}")
        }
    }

    /*
        Initialize the slices schema for the PreKeys and the InitialMessage
     */
    private fun initializeSlices(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")
        val authCode = ctx.request().getParam("authCode")

        if (targetPodId != null && authCode != null) {
            // Placeholder for initializing slices schema
            X3DH.initiateSliceSchema(targetPodId, authCode)

            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Initiate slices to $targetPodId pod\"}")
        } else {
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Pod name and authentication code is required to initiate slices!\"}")
        }
    }

    /*
        Upload the new PreKeys
     */
    private fun uploadPreKeys(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")
        val authCode = ctx.request().getParam("authCode")
        val user = if (targetPodId == "alice") Alice else Bob

        if (authCode != null) {
            X3DH.uploadPreKeys(targetPodId, user.preKeys!!.getPublic(), authCode)
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"PreKeys uploaded for $targetPodId\"}")
        } else {
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Authentication code is required!\"}")
        }
    }

    /*
        Send the initial message
     */
    private fun sendInitialMessage(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")
        val authCode = ctx.request().getParam("authCode")
        val user = if (targetPodId == "alice") Bob else Alice

        if (authCode != null) {
            user.sharedKey = X3DH.sendInitialMessage(user, targetPodId, user.preKeys!!, authCode)
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Initial message sent for $targetPodId\"}")
        } else {
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Authentication code is required!\"}")
        }
    }

    /*
        Process the initial message
     */
    private fun processInitialMessage(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")
        val authCode = ctx.request().getParam("authCode")
        val user = if (targetPodId == "alice") Alice else Bob

        if (targetPodId != null && authCode != null) {
            user.sharedKey = X3DH.processInitialMessage(user, targetPodId, user.preKeys!!, authCode)
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Initial message processed for $targetPodId\"}")
        } else {
            ctx.response().putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Authentication code is required!\"}")
        }
    }

    /*
        Send a new message
     */

    private fun sendMessage(ctx: RoutingContext) {
        val jsonBody = ctx.body().asJsonObject()

        val targetPodId = jsonBody.getString("pod")
        val sender = jsonBody.getString("sender")
        val message = jsonBody.getString("message")
        val timestampString = jsonBody.getString("timestamp")
        val timestampBytes = ByteBuffer.allocate(8).putLong(timestampString.toLong()).array()
        val authCode = jsonBody.getString("authCode")
        val keepStructureParam = jsonBody.getString("keepStructure")
        val keepStructure = keepStructureParam != null && keepStructureParam == "true"

        val valuesToEncryptString = jsonBody.getString("valuesToEncryptString")
        val tripleGroupsToEncryptString = jsonBody.getString("tripleGroupsToEncryptString")

        val encryptionLists = if (keepStructure) processEncryptionLists(valuesToEncryptString, tripleGroupsToEncryptString) else Pair(emptyList(), emptyList())
        val valuesToEncrypt = encryptionLists.first
        val tripleGroupsToEncrypt = encryptionLists.second

        if (targetPodId != null && sender != null && message != null) {
            var encryptedMessage: String?
            if (isNotInitialized) {
                if (sender == "alice") {
                    encryptedMessage = Alice.sendInitialMessage(targetPodId, message.toByteArray(), timestampBytes, authCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt, mocked)
                    isNotInitialized = false
                } else {
                    encryptedMessage = Bob.sendInitialMessage(targetPodId, message.toByteArray(), timestampBytes, authCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt, mocked)
                    isNotInitialized = false
                }
            } else {
                if (sender == "alice") {
                    encryptedMessage = Alice.sendMessage(targetPodId, message.toByteArray(), timestampBytes, authCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt, mocked)
                } else {
                    encryptedMessage = Bob.sendMessage(targetPodId, message.toByteArray(), timestampBytes, authCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt, mocked)
                }
            }
            val jsonResponse = JsonObject()
                .put("message", "Message sent from $sender to $targetPodId pod")
                .put("encryptedMessage", encryptedMessage)

            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end(jsonResponse.encode())
        } else {
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"All parameters (pod, sender, message) are required!\"}")
        }
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

        val targetPodId = jsonBody.getString("pod")
        val user = jsonBody.getString("user")
        val authCode = jsonBody.getString("authCode")
        val keepStructureParam = jsonBody.getString("keepStructure")
        val keepStructure = keepStructureParam != null && keepStructureParam == "true"

        if (targetPodId != null && user != null) {
            val messages = if (user == "alice") Alice.receiveMessage(targetPodId, authCode, keepStructure, mocked) else Bob.receiveMessage(targetPodId, authCode, keepStructure, mocked)

            val jsonResponse = JsonObject().put("messages", messages)

            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end(jsonResponse.encode())
        } else {
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Pod name and user are required to retrieve messages!\"}")
        }
    }
}