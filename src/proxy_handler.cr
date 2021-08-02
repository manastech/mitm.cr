require "http/server/handler"

require "./websocket_handler"

class Mitm::ProxyHandler
  include HTTP::Handler

  Log = Mitm::Log.for("ProxyHandler")

  def initialize(certs_path : String = "./certs", ca : Bool = true)
    @cert_mgr = CertManager.new(certs_path, ca)
    @websocket_handler = WebSocketHandler.new
    @websocket_handler.new_socket_callback = ->open_websocket(String, String, String, ::HTTP::Client::TLSContext, HTTP::Headers, ::HTTP::WebSocket)
    @websocket_handler.next = Proc(::HTTP::Server::Context, Nil).new do |_|
      # We need a proc attached to handler's `next`, so that the handler  won't kill
      # the context, sending 404 to the client, when he hasn't found any websocket.
      next
    end
  end

  def call(context)
    request = context.request

    if request.method == "CONNECT"
      host, port = request.resource.split(":", 2)

      context.response.upgrade do |io|
        magic = io.peek.try &.[1]
        is_secure = false
        if magic && magic < 32
          is_secure = true
          # Binary data means that it's an SSL handshake on the client side
          client = OpenSSL::SSL::Socket::Server.new(io, @cert_mgr.context_for(host))
        else
          client = io
        end

        while client_request = HTTP::Request.from_io(client)
          if client_request.is_a?(HTTP::Request)
            # Create a new server context for this request inside other request
            # and pass it to the following request processors
            proxy_context = WebSocketHandler::ProxyContext.new(
              host,
              port,
              client_request.as(HTTP::Request),
              ::HTTP::Server::Response.new(client),
              is_secure
            )
            @websocket_handler.call(proxy_context)
            if upgrade_handler = proxy_context.response.upgrade_handler
              client.flush
              # This means that the websocket handler kicked in, we can call it
              upgrade_handler.call(client)
            else
              execute_request(host, port, true, client_request) do |upstream_response|
                upstream_response.to_io(client)
                client.flush
              rescue e : Exception
                Log.error(exception: e) { "Error sending yelded response to client: #{e.inspect_with_backtrace}" }
              end
            end
          end
        end
      rescue e : Exception
        Log.error(exception: e) { "Error in proxy: #{e.inspect_with_backtrace}" }
        context.response.status_code = 500
        context.response.print("Error in proxy: #{e.inspect_with_backtrace}")
      end
    elsif request.resource.starts_with?("http://")
      uri = URI.parse(request.resource)

      execute_request(uri.host.not_nil!, uri.port || 80, false, request) do |upstream_response|
        context.response.status_code = upstream_response.status_code
        context.response.headers.merge!(upstream_response.headers)

        if string_body = upstream_response.body?
          context.response.print(string_body)
        elsif body_io = upstream_response.body_io?
          IO.copy(body_io, context.response)
        end
      rescue e : Exception
        Log.error(exception: e) { "Error sending yelded response to client: #{e.inspect_with_backtrace}" }
      end
    else
      call_next(context)
    end
  end

  # Execute request over the target host
  # This method is called each time the request to the target system is created.
  # Redefine it in a subclass to catch outgoing requests.
  def execute_request(host, port, tls, request : HTTP::Request, &block : HTTP::Client::Response ->)
    request.headers.delete("Accept-Encoding")

    HTTP::Client.new(host, port, tls) do |upstream|
      upstream.exec(request) do |upstream_response|
        upstream_response.headers.delete("Transfer-Encoding")
        upstream_response.headers.delete("Content-Encoding")
        upstream_response.headers.delete("Content-Length")
        yield upstream_response
      end
    end
  end

  # Open a websocket to the target host
  # This method is called each time a websocket to the target host needs to
  # be created. Target parameters are supplied with the websocket already
  # connected to the client.
  def open_websocket(host, resource, port, tls, headers, client_ws)
    upstream_ws = ::HTTP::WebSocket.new(
      host: host,
      path: resource,
      port: port,
      tls: tls,
      headers: headers
    )

    Log.info { "New websocket connection: #{host}:#{port}#{resource}, secure: #{tls}" }

    close_message = Proc(Nil).new do
      Log.info { "Websocket closed: #{host}:#{port}#{resource}, secure: #{tls}" }
    end

    client_ws.on_close do |code, message|
      Log.trace { "Client close (#{code}): #{message}" }
      upstream_ws.close(code, message)
      # Both sockets will be closed, so one `close_message.call` is enough
    end

    upstream_ws.on_close do |code, message|
      Log.trace { "Remote close (#{code}): #{message}" }
      client_ws.close(code, message)
      close_message.call
    end

    match_websockets(client_ws, upstream_ws)
    spawn do
      while !upstream_ws.closed?
        upstream_ws.run
      end
    end
  end

  # Connects two websockets to throw messages to each other
  private def match_websockets(client : ::HTTP::WebSocket, upstream : ::HTTP::WebSocket)
    client.on_message do |message|
      Log.trace { "Client websocket message #{message}" }
      upstream.send(message)
    end

    upstream.on_message do |message|
      Log.trace { "Remote websocket message #{message}" }
      client.send(message)
    end

    client.on_binary do |message|
      Log.trace { "Client binary websocket message: #{message.hexstring}" }
      upstream.send(message)
    end

    upstream.on_binary do |message|
      Log.trace { "Upstream binary websocket message: #{message.hexstring}" }
      client.send(message)
    end

    client.on_ping do |message|
      Log.trace { "Client websocket ping #{message}" }
      upstream.ping(message)
    end

    upstream.on_ping do |message|
      Log.trace { "Remote websocket ping #{message}" }
      client.ping(message)
    end

    client.on_pong do |message|
      Log.trace { "Client websocket pong #{message}" }
      upstream.pong(message)
    end

    upstream.on_pong do |message|
      Log.trace { "Remote websocket pong #{message}" }
      client.pong(message)
    end
  end
end
