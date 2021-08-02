require "http/server/handlers/websocket_handler"

# The class is a websocket handler, that lets the websockets go through the proxy to the target host
class Mitm::WebSocketHandler < ::HTTP::WebSocketHandler
  # Proxy context to be passed to the handler.
  # This context is created upon processing of the CONNECT method and passed
  # to the websocket handler. If it contains a websocket request, it is
  # processed by the handler. Otherwise it gets returned by the call_next method.
  # Additional parameters are added after the processing of the original request.
  class ProxyContext < ::HTTP::Server::Context
    getter ssl, host, port

    def initialize(
      @host : String,
      @port : String,
      request : ::HTTP::Request,
      response : ::HTTP::Server::Response,
      @ssl = false
    )
      super(request, response)
    end
  end

  # Proc to call when a websocket to the target host needs to be created.
  # Make sure you assign it, or client socket will be immediately closed
  property new_socket_callback : Proc(String, String, String, ::HTTP::Client::TLSContext, HTTP::Headers, ::HTTP::WebSocket, Nil)? = nil

  def initialize
    super do |ws, context|
      unless ctx = context.as?(WebSocketHandler::ProxyContext)
        context.response.respond_with_status(:internal_server_error)
        next
      end

      host = ctx.host
      resource = ctx.request.resource
      port = ctx.port
      secure = ctx.ssl
      headers = ctx.request.headers

      if callback = @new_socket_callback
        callback.call(host, resource, port, secure, headers, ws)
      else
        ws.close(:internal_server_error, "Internal proxy error")
      end
    end
  end
end
