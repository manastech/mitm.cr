require "http/server/handler"

class Mitm::ProxyHandler
  include HTTP::Handler

  def call(context)
    request = context.request

    if request.method == "CONNECT"
      host, port = request.resource.split(":", 2)

      context.response.upgrade do |io|
        client = OpenSSL::SSL::Socket::Server.new(io, Mitm::CertManager.context_for(host))
        HTTP::Client.new(host, port, tls: true) do |upstream|
          while client_request = HTTP::Request.from_io(client)
            if client_request.is_a?(HTTP::Request)
              upstream.exec(client_request) do |server_response|
                server_response.to_io(client)
              end

              client.flush
            end
          end
        end
      end
    elsif request.resource.starts_with?("http://")
      uri = URI.parse(request.resource)
      HTTP::Client.new(uri.host.not_nil!, uri.port || 80) do |upstream|
        upstream.exec(request) do |upstream_response|
          context.response.status_code = upstream_response.status_code
          context.response.headers.merge!(upstream_response.headers)
          IO.copy(upstream_response.body_io, context.response)
        end
      end
    else
      call_next(context)
    end
  end
end
