package security

import io.vertx.core.AbstractVerticle
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import security.crypto.generatePrekeys
import java.nio.ByteBuffer

class MainVerticle : AbstractVerticle() {
    val Alice = User("alice")
    val Bob = User("bob")
    var isNotInitialized = true

    override fun start() {
        // Initialize Alice and Bob
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()



        // Create an HTTP server and router
        val router = Router.router(vertx)

        // Serve the HTML page at the root URL
        router.get("/").handler(this::serveHtmlPage)

        // Define the endpoint to initiate the X3DH key agreement
        router.get("/initiateX3DH").handler(this::initiateX3DH)

        // Define the endpoint to send a message
        router.get("/sendMessage").handler(this::sendMessage)

        //Define the endpoint to retrieve the messages
        router.get("/retrieveMessages").handler(this::retrieveMessages)

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
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="top-section">
                        <h1>Communication Pod</h1>
                        <label for="podName">Enter Target Pod Name:</label>
                        <input type="text" id="podName" placeholder="Pod Name">
                        <button onclick="initiateX3DH()">Initiate X3DH</button>
                    </div>
    
                    <div class="input-container">
                        <div>
                            <h2>Alice's Messages</h2>
                            <input type="text" id="aliceMessage" placeholder="Enter Alice's message">
                            <button onclick="sendMessage('alice')">Send</button>
                        </div>
                        <div>
                            <h2>Bob's Messages</h2>
                            <input type="text" id="bobMessage" placeholder="Enter Bob's message">
                            <button onclick="sendMessage('bob')">Send</button>
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
                    </div>
                </div>

                <script>
                    let aliceInbox = [];
                    let bobInbox = [];
                    let podName = '';
                    
                    function initiateX3DH() {
                        podName = document.getElementById('podName').value;
                        if (podName) {
                            fetch('/initiateX3DH?pod=' + podName)
                                .then(response => response.json())
                                .then(data => {
                                    alert(data.message);
                                })
                                .catch(err => console.error('Error:', err));
                        } else {
                            alert('Please enter a pod first!');
                        }
                    }

                    function sendMessage(sender) {
                        const message = sender === 'alice' ? document.getElementById('aliceMessage').value : document.getElementById('bobMessage').value;
                        if (message) {
                            const timestamp = Date.now();
                            
                            if (sender === 'alice') {
                                aliceInbox.push({ sender: sender, content: message, timestamp: timestamp });
                            } else {
                                bobInbox.push({ sender: sender, content: message, timestamp: timestamp });
                            }
                            
                            fetch('/sendMessage?pod=' + podName + '&sender=' + sender + '&message=' + encodeURIComponent(message) + '&timestamp=' + timestamp)
                                .then(response => response.json())
                                .then(data => {
                                    alert(data.message);
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
                        fetch('/retrieveMessages?pod=' + podName + '&user=' + user)
                            .then(response => response.json())
                            .then(data => {
                                const inbox = user === 'alice' ? aliceInbox : bobInbox;
                                const receiver = user === "alice" ? "alice" : "bob";
                                const sender = user === 'alice' ? 'bob' : 'alice';

                                data.messages.forEach(msg => {
                                    const plainTextMatch = msg.match(/plainText=([^,]+)/);
                                    const plainText = plainTextMatch ? plainTextMatch[1] : null;
                                    
                                    // Extract timestamp
                                    const timestampMatch = msg.match(/timestamp=(\d+)/);
                                    const timestamp = timestampMatch ? Number(timestampMatch[1]) : null;
                                                                        
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

    private fun initiateX3DH(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")

        if (targetPodId != null) {
            X3DH.uploadPreKeys(targetPodId, Bob.preKeys!!.getPublic())
            Alice.sharedKey = X3DH.sendInitialMessage(Alice, targetPodId, Alice.preKeys!!)
            Bob.sharedKey = X3DH.processInitialMessage(Bob, targetPodId, Bob.preKeys!!)

            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"X3DH initiated for pod '$targetPodId'\"}")
        } else {
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Pod name is required to initiate X3DH!\"}")
        }
    }

    // Endpoint to send a message
    private fun sendMessage(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")
        val sender = ctx.request().getParam("sender")
        val message = ctx.request().getParam("message")
        val timestampString = ctx.request().getParam("timestamp")
        val timestampBytes = ByteBuffer.allocate(8).putLong(timestampString.toLong()).array()

        if (targetPodId != null && sender != null && message != null) {

            if (isNotInitialized) {
                if (sender == "alice") {
                    Alice.sendInitialMessage(targetPodId, message.toByteArray(), timestampBytes)
                    isNotInitialized = false
                } else {
                    Bob.sendInitialMessage(targetPodId, message.toByteArray(), timestampBytes)
                    isNotInitialized = false
                }
            } else {
                if (sender == "alice") {
                    Alice.sendMessage(targetPodId, message.toByteArray(), timestampBytes)
                } else {
                    Bob.sendMessage(targetPodId, message.toByteArray(), timestampBytes)
                }
            }
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Message sent from $sender to $targetPodId pod\"}")
        } else {
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"All parameters (pod, sender, message) are required!\"}")
        }
    }

    private fun retrieveMessages(ctx: RoutingContext) {
        val targetPodId = ctx.request().getParam("pod")
        val user = ctx.request().getParam("user")

        if (targetPodId != null && user != null) {
            val messages = if (user == "alice") Alice.receiveMessage(targetPodId) else Bob.receiveMessage(targetPodId)

            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"messages\": ${messages.map { "\"$it\"" }}}")
        } else {
            ctx.response()
                .putHeader("Content-Type", "application/json")
                .end("{\"message\": \"Pod name and user are required to retrieve messages!\"}")
        }
    }
}