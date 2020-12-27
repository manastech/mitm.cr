require "http/server/handler"

class Mitm::ProxyHandler
  include HTTP::Handler

  Log = ::Log.for("Mitm::ProxyHandler")

  def initialize(certs_path : String = "./certs", ca : Bool = true)
    @cert_mgr = CertManager.new(certs_path, ca)
  end

  def call(context)
    request = context.request

    if request.method == "CONNECT"
      host, port = request.resource.split(":", 2)

      context.response.upgrade do |io|
        client = OpenSSL::SSL::Socket::Server.new(io, @cert_mgr.context_for(host))

        while client_request = HTTP::Request.from_io(client)
          if client_request.is_a?(HTTP::Request)
            execute_request(host, port, true, client_request) do |upstream_response|
              upstream_response.to_io(client)
              client.flush
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
      end
    else
      call_next(context)
    end
  end

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
end
