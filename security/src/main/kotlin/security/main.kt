package security


import io.vertx.core.AbstractVerticle
import io.vertx.core.Vertx
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import security.crypto.generatePrekeys


fun main() {
    val vertx = Vertx.vertx()
    vertx.deployVerticle(MainVerticle())
}
